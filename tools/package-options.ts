export interface PackageOptionsEnvironment {
  JJ_VAULT_STAGE_ONLY?: string;
  JJ_VAULT_SIGN_IDENTITY?: string;
}

export interface PackageOptions {
  install: boolean;
  stageOnly: boolean;
  signingIdentity: string;
  entitlements: string;
  signingStatus: string;
}

/** Resolve all user options before the packaging entry point creates files. */
export function resolvePackageOptions(
  args: readonly string[],
  environment: PackageOptionsEnvironment,
  readSigningIdentities?: () => string,
): PackageOptions {
  for (const argument of args) {
    if (argument !== '--install') throw new Error(`Unknown packaging option: ${argument}`);
  }
  if (args.length > 1) throw new Error('The --install option may only be provided once.');

  const install = args.includes('--install');
  if (install && environment.JJ_VAULT_STAGE_ONLY === '1') {
    throw new Error('--install conflicts with JJ_VAULT_STAGE_ONLY=1. Remove one of these options.');
  }

  const configuredIdentity = environment.JJ_VAULT_SIGN_IDENTITY;
  let signingIdentity = '-';
  if (configuredIdentity !== undefined) {
    const requestedIdentity = configuredIdentity.trim();
    if (!requestedIdentity || requestedIdentity === '-') {
      throw new Error('JJ_VAULT_SIGN_IDENTITY must name an installed signing identity. Omit it for ad hoc signing.');
    }
    if (!readSigningIdentities) throw new Error('Cannot inspect the requested signing identity.');
    const identities = readSigningIdentities().split(/\r?\n/).flatMap(line => {
      const match = /^\s*\d+\)\s+([a-fA-F0-9]{40})\s+"([^"]+)"\s*$/.exec(line);
      return match ? [{ fingerprint: match[1]!, name: match[2]! }] : [];
    });
    const identity = identities.find(candidate => candidate.name === requestedIdentity
      || candidate.fingerprint.toUpperCase() === requestedIdentity.toUpperCase());
    if (!identity) throw new Error(`Requested signing identity is unavailable: ${requestedIdentity}`);
    signingIdentity = identity.fingerprint;
  }

  return {
    install,
    stageOnly: !install,
    signingIdentity,
    entitlements: signingIdentity === '-' ? 'assets/entitlements.mac.adhoc.plist' : 'assets/entitlements.mac.plist',
    signingStatus: signingIdentity === '-'
      ? 'Ad hoc signed. No named signing identity was requested.'
      : `Signed with configured identity ${configuredIdentity!.trim()}.`,
  };
}
