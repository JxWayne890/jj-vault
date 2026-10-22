import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Node canonicalizes module URLs, including parent aliases such as /var. */
export function isDirectExecution(moduleUrl: string | undefined, argument = process.argv[1]): boolean {
  if (typeof moduleUrl !== 'string' || !argument) return false;
  try { return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(resolve(argument)); }
  catch { return false; }
}
