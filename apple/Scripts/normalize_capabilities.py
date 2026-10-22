#!/usr/bin/env python3
"""Repair nested capability attributes emitted as strings by XcodeGen 2.46.

Newer XcodeGen versions emit proper dictionaries, which this leaves unchanged.
The source entitlements remain authoritative and are never altered here.
"""
import json
from pathlib import Path
import re
import subprocess
import sys

project = Path(sys.argv[1] if len(sys.argv) > 1 else "JJVault.xcodeproj/project.pbxproj")
text = project.read_text()
entry = re.compile(r'(?m)^([ \t]*)SystemCapabilities = ("(?:\\.|[^"\\])*");[ \t]*$')
capability = re.compile(r'"([A-Za-z0-9._-]+)"\s*:\s*\[\s*"enabled"\s*:\s*([01])\s*\]')

def normalize(match):
    indent, encoded = match.groups()
    description = json.loads(encoded)
    pairs = capability.findall(description)
    residue = capability.sub("", description)
    if not pairs or not re.fullmatch(r'[\[\],\s]*', residue):
        raise ValueError("Unsupported string capability attribute; preserve source and update XcodeGen")
    if len(dict(pairs)) != len(pairs):
        raise ValueError("Duplicate capability attribute")
    rows = [indent + "SystemCapabilities = {"]
    for name, enabled in sorted(pairs):
        rows += [indent + "\t" + name + " = {", indent + "\t\tenabled = " + enabled + ";", indent + "\t};"]
    return "\n".join(rows + [indent + "};"])

updated, count = entry.subn(normalize, text)
if count:
    project.write_text(updated)
subprocess.run(["/usr/bin/plutil", "-lint", str(project)], check=True)
print("Normalized " + str(count) + " capability attributes")
