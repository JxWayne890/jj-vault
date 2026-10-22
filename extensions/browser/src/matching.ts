/** Exact hosts prevent lookalike and sibling subdomain fills. Ports must agree. */
export function matchesUrl(saved: string, page: string): boolean {
  try {
    const a = new URL(saved), b = new URL(page);
    if (!['https:', 'http:'].includes(a.protocol) || !['https:', 'http:'].includes(b.protocol)) return false;
    if (a.username || a.password || b.username || b.password) return false;
    if (a.hostname !== b.hostname || a.port !== b.port) return false;
    return !(a.protocol === 'https:' && b.protocol !== 'https:');
  } catch { return false; }
}

/** Browser fills require TLS, including identity and card fields. */
export function safePageUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 8192) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && Boolean(url.hostname);
  } catch { return false; }
}

export function sameDocument(expected: string, actual: string): boolean {
  // Ignore a fragment change only. Every other navigation invalidates the response.
  try {
    const a = new URL(expected), b = new URL(actual);
    a.hash = ''; b.hash = '';
    return safePageUrl(expected) && safePageUrl(actual) && a.href === b.href;
  } catch { return false; }
}

export function acceptCapture(sender: { id?: string; frameId?: number; tab?: { id?: number; url?: string } }, runtimeId: string, candidate: unknown, now = Date.now()): boolean {
  if (sender.id !== runtimeId || sender.frameId !== 0 || !Number.isInteger(sender.tab?.id)) return false;
  if (!candidate || typeof candidate !== 'object') return false;
  const value = candidate as Record<string, unknown>;
  if (!safePageUrl(value.url) || !safePageUrl(sender.tab?.url) || !sameDocument(value.url, sender.tab.url)) return false;
  if (typeof value.password !== 'string' || value.password.length < 1 || value.password.length > 4096) return false;
  if (typeof value.username !== 'string' || value.username.length > 4096 || typeof value.title !== 'string' || value.title.length > 512) return false;
  return typeof value.capturedAt === 'number' && value.capturedAt <= now + 1000 && now - value.capturedAt < 10_000;
}
