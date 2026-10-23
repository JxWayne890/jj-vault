/** Give native connection failures a useful next step without exposing setup details. */
export function cleanError(error: unknown): string {
  const message = error instanceof Error ? error.message : 'JJ Vault could not complete the request.';
  // Chrome's forbidden error also contains "specified native messaging host".
  // Check authorization before missing registration so a wrong ID is actionable.
  if (/native messaging host.*(?:forbidden|not authori[sz]ed)|(?:forbidden|not authori[sz]ed).*native messaging host/i.test(message)) {
    return 'This extension ID is not authorized. Compare the ID under Connect this browser with the ID paired in the Mac app, then pair this extension again.';
  }
  if (/native messaging host not found|host.*not found|not.*registered/i.test(message)) {
    return 'Pair this extension with the Mac app using the setup steps below.';
  }
  if (/not.*connect|connection refused|exited|disconnected|failed to connect/i.test(message)) {
    return 'Open JJ Vault on your Mac, unlock it, and try again.';
  }
  if (/locked/i.test(message)) return 'Vault is locked. Unlock JJ Vault on your Mac, then refresh.';
  return message.slice(0, 240);
}
