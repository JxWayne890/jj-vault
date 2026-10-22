import { access, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installBrowserHost as installHost, type BrowserInstallOperation, type BrowserInstallResult } from '../packages/service/src/browser-install.ts';
import { isDirectExecution } from '../packages/service/src/entrypoint.ts';

export interface BrowserInstallOptions {
  /** Fixture overrides are never accepted from command line arguments. */
  homeDirectory?: string;
  dataDirectory?: string;
  sourceHostFile?: string;
  preferredNode?: string;
  runtimePath?: string;
  runAsNode?: boolean;
  port?: number;
  browserTokenFile?: string;
}
export type { BrowserInstallResult };

async function chooseNode(preferred: string) {
  try { if ((await stat(preferred)).isFile()) { await access(preferred, constants.X_OK); return preferred; } } catch { /* Use the installer runtime when the preferred Node is unavailable. */ }
  await access(process.execPath, constants.X_OK);
  return process.execPath;
}
export function parseBrowserInstallArguments(args: string[]): BrowserInstallOperation[] {
  if (!args.length) throw new Error('Choose a browser to pair or remove.');
  const operations: BrowserInstallOperation[] = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--chrome' || argument === '--remove-chrome') {
      const id = args[++index];
      if (!id || !/^[a-p]{32}$/.test(id)) throw new Error('Chrome extension IDs must contain 32 letters from a through p.');
      operations.push({ action: argument === '--chrome' ? 'chrome' : 'removeChrome', id });
    } else if (argument === '--firefox') operations.push({ action: 'firefox', id: 'jjvault@john.local' });
    else if (argument === '--remove-firefox') operations.push({ action: 'removeFirefox', id: 'jjvault@john.local' });
    else throw new Error('Unknown browser setup argument.');
  }
  return operations;
}
/** Preserve the command line wrapper's programmatic API for source users. */
export async function installBrowserHost(args: string[], options: BrowserInstallOptions = {}): Promise<BrowserInstallResult> {
  const operations = parseBrowserInstallArguments(args);
  return installHost({
    operations,
    ...options,
    sourceHostFile: path.resolve(options.sourceHostFile ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '../dist/service/native-host.cjs')),
    runtimePath: options.runtimePath ?? await chooseNode(options.preferredNode ?? '/opt/homebrew/bin/node'),
  });
}
async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.length === 0) {
    process.stdout.write('Pair a browser with the local JJ Vault app.\n\nUsage:\n  npx tsx tools/install-browser-host.ts --chrome EXTENSION_ID\n  npx tsx tools/install-browser-host.ts --firefox\n  npx tsx tools/install-browser-host.ts --remove-chrome EXTENSION_ID\n  npx tsx tools/install-browser-host.ts --remove-firefox\n\nOpen JJ Vault and enable browser access before pairing. No password or token is printed.\n'); return;
  }
  const result = await installBrowserHost(args);
  process.stdout.write(`Paired ${result.chromeCount} Chrome and ${result.firefoxCount} Firefox extension IDs. The bridge is installed in local Application Support. Restart the browser and open JJ Vault.\n`);
}
if (isDirectExecution(import.meta.url)) main().catch(error => { process.stderr.write(`${error instanceof Error ? error.message : 'Browser setup failed'}\n`); process.exitCode = 1; });
