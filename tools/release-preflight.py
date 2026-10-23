#!/usr/bin/env python3
"""Read only source release check. Never reads vaults or follows source symlinks."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = ("apps", "packages", "extensions", "tools", "docs", "assets", "apple", ".github")
ROOT_FILES = ("README.md", "package.json", "package-lock.json", "tsconfig.json", ".gitignore", "LICENSE", "SECURITY.md", "CONTRIBUTING.md")
SKIP = {".git", ".build", ".swiftpm", "build", "dist", "release", "output", "coverage", "test-results", "playwright-report", "node_modules", "DerivedData", "xcuserdata", "__pycache__", ".vercel"}
DATALESS = 0x40000000  # macOS SF_DATALESS, checked before any content read.
PRIVATE_NAMES = {"source-provenance.json", "RECOVERY-PROVENANCE.md", ".env", ".env.local", "vault.json", "relay.json", "relay-token", "browser-token", "agent-token"}
PRIVATE_SUFFIXES = {".1pux", ".1pif", ".jjbackup", ".jjvault", ".sqlite", ".sqlite3", ".db", ".key", ".pem", ".p12", ".pfx", ".mobileprovision", ".csv", ".tsv"}
TEXT_SUFFIXES = {".ts", ".js", ".mjs", ".py", ".swift", ".json", ".yaml", ".yml", ".md", ".html", ".css", ".svg", ".plist", ".entitlements", ".c", ".h", ".sh", ".txt", ".map", ".pbxproj", ".xcscheme", ".xcworkspacedata"}
SYNTHETIC_KEY_FIXTURES = {"packages/core/test/fixtures/interop.json", "apple/Tests/JJVaultCoreTests/interop.json", "apple/Tests/JJVaultCoreTests/conflict.json"}
SECRET_RULES = {
    "private-key-material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-access-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "supabase-secret-key": re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b"),
    "jwt-literal": re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
    "vault-secret-key": re.compile(r"\bJJ1\.[A-Za-z0-9_-]{43}\b"),
}
LOCAL_PATH = re.compile(r"(?:/Users|/home)/[A-Za-z0-9_.-]+/")
HOSTED_URL = re.compile(r"https://([A-Za-z0-9.-]+\.(?:supabase\.co|vercel\.app))\b", re.I)
SYNTHETIC_HOSTS = {"abcdefghijklmnopqrst.supabase.co", "yourprojectreference.supabase.co", "your-project.vercel.app", "yourproject.vercel.app"}
SIGNING_TEAM = re.compile(r"(?:DEVELOPMENT_TEAM|DevelopmentTeam|developmentTeam|TEAM_ID)\s*[:=]\s*[\"']?([A-Z0-9]{10})\b")
PLACEHOLDER_TEAMS = {"YOURTEAMID", "EXAMPLETEAM", "ABCDEFGHIJ", "TEAMID1234", "XXXXXXXXXX"}


def private_artifact(path):
    data_name = path.name.startswith(("device-secret", "device-pin", "session-key", "relay-token", "browser-token")) and path.suffix.lower() in {"", ".json", ".bin", ".enc", ".txt"}
    return path.name in PRIVATE_NAMES or data_name or path.name.startswith(".device-pin-") or (path.name.startswith(".env.") and path.name != ".env.example") or path.suffix.lower() in PRIVATE_SUFFIXES


def inventory(root):
    files, offloaded, symlinks, private = [], [], [], []

    def add(p):
        info = p.lstat()
        relative = p.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            symlinks.append(relative)
        elif stat.S_ISREG(info.st_mode) and private_artifact(p):
            private.append(relative)
        elif stat.S_ISREG(info.st_mode):
            files.append(relative)
            if getattr(info, "st_flags", 0) & DATALESS:
                offloaded.append(relative)

    for name in ROOT_FILES:
        p = root / name
        if p.exists():
            add(p)
    # Classify private root artifacts by metadata only, even though they are not
    # part of the allowlisted source inventory. Never open their contents.
    for p in root.iterdir():
        if private_artifact(p):
            info = p.lstat()
            if stat.S_ISLNK(info.st_mode):
                symlinks.append(p.relative_to(root).as_posix())
            elif stat.S_ISREG(info.st_mode):
                private.append(p.relative_to(root).as_posix())
    for name in SOURCE_ROOTS:
        top = root / name
        if top.is_symlink():
            symlinks.append(name)
            continue
        for current, directories, names in os.walk(top, followlinks=False):
            retained = []
            for name in sorted(directories):
                p = Path(current) / name
                if name in SKIP or name.startswith(("dist.", "node_modules.")):
                    continue
                if p.is_symlink():
                    symlinks.append(p.relative_to(root).as_posix())
                else:
                    retained.append(name)
            directories[:] = retained
            for name in sorted(names):
                if name != ".DS_Store":
                    add(Path(current) / name)
    return sorted(files), sorted(offloaded), sorted(symlinks), sorted(set(private))


def scan_source(root, files, offloaded):
    findings, fixtures = [], []
    unavailable = set(offloaded)
    for relative in files:
        p = root / relative
        if relative in unavailable or (p.suffix.lower() not in TEXT_SUFFIXES and p.name not in {"LICENSE", ".gitignore", ".env.example"}):
            continue
        # Check again immediately before reading. Offloaded data and symlinks
        # never become a content scan, even if source changed after inventory.
        info = p.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_flags", 0) & DATALESS:
            findings.append({"path": relative, "rule": "source-changed-before-scan"})
            continue
        if info.st_size > 5 * 1024 * 1024:
            findings.append({"path": relative, "rule": "source-too-large-for-literal-scan"})
            continue
        try:
            descriptor = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "r", encoding="utf-8") as source:
                opened = os.fstat(source.fileno())
                if not stat.S_ISREG(opened.st_mode) or getattr(opened, "st_flags", 0) & DATALESS:
                    findings.append({"path": relative, "rule": "source-changed-before-scan"})
                    continue
                if opened.st_size > 5 * 1024 * 1024:
                    findings.append({"path": relative, "rule": "source-too-large-for-literal-scan"})
                    continue
                content = source.read(5 * 1024 * 1024 + 1)
        except (UnicodeError, OSError):
            findings.append({"path": relative, "rule": "source-not-readable-as-text"})
            continue
        for number, line in enumerate(content.splitlines(), 1):
            for rule, pattern in SECRET_RULES.items():
                if pattern.search(line):
                    item = {"path": relative, "line": number, "rule": rule}
                    if rule == "vault-secret-key" and relative in SYNTHETIC_KEY_FIXTURES:
                        fixtures.append(item)
                    else:
                        findings.append(item)
            if LOCAL_PATH.search(line):
                # Tests can assert that generated commands contain no fixed user
                # path. This reviewed negative assertion is not a runtime path.
                if not (relative == "tools/test-agent-management.ts" and "assert.equal(command.includes(" in line and ", false)" in line):
                    findings.append({"path": relative, "line": number, "rule": "local-user-path"})
            if any(match.group(1).lower() not in SYNTHETIC_HOSTS for match in HOSTED_URL.finditer(line)):
                findings.append({"path": relative, "line": number, "rule": "hosted-project-url"})
            if any(match.group(1) not in PLACEHOLDER_TEAMS for match in SIGNING_TEAM.finditer(line)):
                findings.append({"path": relative, "line": number, "rule": "apple-signing-team-id"})
    return findings, fixtures


def candidate_git(root, arguments, data=None):
    # Use only this candidate's own Git directory, never an ancestor checkout or
    # Git environment override. This reads index paths/config, not old history.
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull})
    return subprocess.run(["git", "--git-dir", str(root / ".git"), "--work-tree", str(root), *arguments],
                          cwd=root, env=environment, input=data, capture_output=True, text=True, timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-files", action="store_true", help="Include the allowlisted source paths in the JSON report")
    options = parser.parse_args()
    files, offloaded, symlinks, private = inventory(ROOT)
    findings, fixtures = scan_source(ROOT, files, offloaded)
    blockers = []
    if offloaded:
        blockers.append("Source files are offloaded in iCloud. Restore them before building or publishing.")
    if symlinks:
        blockers.append("Review source symlinks before assembling a clean release.")
    if not (ROOT / "LICENSE").is_file():
        blockers.append("Choose and add the source license before distribution.")
    if findings:
        blockers.append("Review flagged source literals. The report includes only paths and rule names, never matched values.")
    git_directory = ROOT / ".git"
    own_git = git_directory.is_dir() and not git_directory.is_symlink()
    index = ROOT / ".git" / "index"
    index_symlink = index.is_symlink()
    index_offloaded = index.exists() and bool(getattr(index.lstat(), "st_flags", 0) & DATALESS)
    if index_offloaded:
        blockers.append("The Git index is offloaded. Tracked files and history have not been cleared for publication.")
    if index_symlink:
        blockers.append("The candidate Git index is a symlink and will not be inspected.")
    remote_present = False
    tracked_excluded, untracked, private_not_ignored = [], [], list(private)
    git_review_complete = False
    if own_git and not index_offloaded and not index_symlink:
        try:
            result = candidate_git(ROOT, ["remote"])
            remote_present = result.returncode == 0 and bool(result.stdout.strip())
            selected = candidate_git(ROOT, ["ls-files", "-z", "--cached"])
            if selected.returncode == 0:
                tracked = set(filter(None, selected.stdout.split("\0")))
                tracked_excluded = sorted(tracked - set(files))
                untracked = sorted(set(files) - tracked)
                git_review_complete = True
            if private:
                ignored = candidate_git(ROOT, ["check-ignore", "--no-index", "-z", "--stdin"], "\0".join(private) + "\0")
                if ignored.returncode in {0, 1}:
                    private_not_ignored = sorted(set(private) - set(filter(None, ignored.stdout.split("\0"))))
        except (subprocess.TimeoutExpired, OSError):
            pass
    if not own_git:
        blockers.append("The source candidate needs its own fresh Git repository before publication. No ancestor repository or original history was inspected.")
    elif not git_review_complete:
        blockers.append("The candidate Git index could not be reviewed.")
    if tracked_excluded:
        blockers.append("Tracked files fall outside the public source allowlist. Remove private or generated artifacts from the release index.")
    if untracked:
        blockers.append("Some selected source files are not in the candidate Git index yet.")
    if private_not_ignored:
        blockers.append("Private artifacts need explicit exclusion before staging the public source.")
    if not remote_present:
        blockers.append("No Git remote is configured or its configuration could not be read.")
    report = {
        "automatedPrerequisitesMet": not blockers,
        "publicationStatus": "Requires source, history and product verification before publication",
        "sourceFiles": len(files),
        "offloadedSourceFiles": offloaded,
        "sourceSymlinks": symlinks,
        "privateArtifactsExcludedFromInventory": private,
        "privateArtifactsNotIgnored": private_not_ignored,
        "sourceLiteralReview": findings,
        "knownSyntheticKeyFixtures": fixtures,
        "candidateOwnGitRepository": own_git,
        "trackedFilesOutsideSourceAllowlist": tracked_excluded,
        "untrackedSourceFiles": untracked,
        "gitIndexOffloaded": bool(index_offloaded),
        "gitRemoteConfigured": remote_present,
        "blockers": blockers,
        "requiredHumanReview": [
            "Publish only a fresh source history. Review the final staged diff; ignore rules do not remove tracked artifacts.",
            "Verify a fresh installation, real Chrome native messaging, backup restoration and supported device flows.",
            "Review hosted readiness separately. A ciphertext relay does not provide remote agent decryption.",
        ],
        "scope": "Allowlisted source text and metadata only. Private artifacts, dependency trees, generated QA output and original Git history were not read. Literal checks are limited signatures, not a security certification. This tool never publishes files.",
    }
    if options.list_files:
        report["selectedSourceFiles"] = files
    print(json.dumps(report, indent=2))
    return 1 if blockers else 0


if __name__ == "__main__":
    sys.exit(main())
