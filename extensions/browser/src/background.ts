import { acceptCapture, matchesUrl, safePageUrl, sameDocument } from './matching.ts';
import { extensionAPI, type LoginCandidate } from './types.ts';

const api = extensionAPI();
const pending = new Map<number, LoginCandidate>();
const TTL = 90_000;

async function clear(tabId: number) {
  const candidate = pending.get(tabId);
  if (candidate) { candidate.password = ''; candidate.username = ''; }
  pending.delete(tabId);
  await Promise.allSettled([
    api.action.setBadgeText({ tabId, text: '' }),
    api.tabs.sendMessage(tabId, { action: 'captureCleared' }, { frameId: 0 }),
  ]);
}

function contentSender(sender: any): boolean {
  return sender.id === api.runtime.id && sender.frameId === 0 && Number.isInteger(sender.tab?.id) && safePageUrl(sender.tab.url) && (sender.url === undefined || sameDocument(sender.url, sender.tab.url));
}

async function currentCapture(tabId: number): Promise<LoginCandidate | null> {
  const candidate = pending.get(tabId);
  if (!candidate) return null;
  const tab = await api.tabs.get(tabId);
  if (pending.get(tabId) !== candidate) return null;
  if (Date.now() >= candidate.capturedAt + TTL || !safePageUrl(tab.url) || !matchesUrl(candidate.url, tab.url)) {
    await clear(tabId); return null;
  }
  return candidate;
}

api.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== api.runtime.id) return;
  if (message?.action === 'capture') {
    if (!acceptCapture(sender, api.runtime.id, message.candidate)) { respond({ ok: false }); return; }
    const tabId = sender.tab.id as number;
    void clear(tabId).then(async () => {
      const tab = await api.tabs.get(tabId);
      if (!safePageUrl(tab.url) || !matchesUrl(message.candidate.url, tab.url)) { message.candidate.password = ''; message.candidate.username = ''; respond({ ok: false }); return; }
      pending.set(tabId, message.candidate);
      await api.action.setBadgeBackgroundColor({ tabId, color: '#c8ed9f' });
      await api.action.setBadgeText({ tabId, text: '1' });
      setTimeout(() => { if (pending.get(tabId) === message.candidate) void clear(tabId); }, Math.max(0, message.candidate.capturedAt + TTL - Date.now()));
      respond({ ok: true, available: true, expiresAt: message.candidate.capturedAt + TTL });
    }).catch(() => { void clear(tabId); respond({ ok: false }); });
    return true;
  }
  // Content pages receive only availability and expiry, never captured fields.
  if (['captureOffer', 'reviewCapture', 'dismissCaptureOffer'].includes(message?.action)) {
    if (!contentSender(sender)) { respond({ ok: false }); return; }
    const tabId = sender.tab.id as number;
    void (async () => {
      const candidate = await currentCapture(tabId);
      if (!candidate) { respond({ ok: true, available: false }); return; }
      if (message.action === 'dismissCaptureOffer') { await clear(tabId); respond({ ok: true, available: false }); return; }
      if (message.action === 'captureOffer') { respond({ ok: true, available: true, expiresAt: candidate.capturedAt + TTL }); return; }
      const [active] = await api.tabs.query({ active: true, currentWindow: true });
      if (active?.id !== tabId || !safePageUrl(active.url) || !sameDocument(sender.tab.url, active.url) || pending.get(tabId) !== candidate || Date.now() >= candidate.capturedAt + TTL) { respond({ ok: false, available: false }); return; }
      if (!api.action.openPopup) { respond({ ok: true, available: true, opened: false }); return; }
      try { await api.action.openPopup(); respond({ ok: true, available: true, opened: true }); }
      catch { respond({ ok: true, available: true, opened: false }); }
    })().catch(() => respond({ ok: false, available: false }));
    return true;
  }
  // A page content script is never allowed to read a captured password.
  if (sender.tab || sender.frameId !== undefined || !Number.isInteger(message?.tabId)) return;
  if (message.action === 'clearCapture') { void clear(message.tabId).then(() => respond({ ok: true })); return true; }
  if (message.action === 'pendingCapture') {
    void currentCapture(message.tabId).then(candidate => respond({ ok: true, candidate })).catch(() => respond({ ok: false }));
    return true;
  }
});

api.tabs.onRemoved.addListener(tabId => { void clear(tabId); });
api.tabs.onUpdated?.addListener((tabId, change) => {
  const candidate = pending.get(tabId);
  if (candidate && change.url !== undefined && (!safePageUrl(change.url) || !matchesUrl(candidate.url, change.url))) void clear(tabId);
});
