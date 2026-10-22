"use strict";
(() => {
  // extensions/browser/src/matching.ts
  function matchesUrl(saved, page) {
    try {
      const a = new URL(saved), b = new URL(page);
      if (!["https:", "http:"].includes(a.protocol) || !["https:", "http:"].includes(b.protocol)) return false;
      if (a.username || a.password || b.username || b.password) return false;
      if (a.hostname !== b.hostname || a.port !== b.port) return false;
      return !(a.protocol === "https:" && b.protocol !== "https:");
    } catch {
      return false;
    }
  }
  function safePageUrl(value) {
    if (typeof value !== "string" || value.length > 8192) return false;
    try {
      const url = new URL(value);
      return url.protocol === "https:" && !url.username && !url.password && Boolean(url.hostname);
    } catch {
      return false;
    }
  }
  function sameDocument(expected, actual) {
    try {
      const a = new URL(expected), b = new URL(actual);
      a.hash = "";
      b.hash = "";
      return safePageUrl(expected) && safePageUrl(actual) && a.href === b.href;
    } catch {
      return false;
    }
  }
  function acceptCapture(sender, runtimeId, candidate, now = Date.now()) {
    if (sender.id !== runtimeId || sender.frameId !== 0 || !Number.isInteger(sender.tab?.id)) return false;
    if (!candidate || typeof candidate !== "object") return false;
    const value = candidate;
    if (!safePageUrl(value.url) || !safePageUrl(sender.tab?.url) || !sameDocument(value.url, sender.tab.url)) return false;
    if (typeof value.password !== "string" || value.password.length < 1 || value.password.length > 4096) return false;
    if (typeof value.username !== "string" || value.username.length > 4096 || typeof value.title !== "string" || value.title.length > 512) return false;
    return typeof value.capturedAt === "number" && value.capturedAt <= now + 1e3 && now - value.capturedAt < 1e4;
  }

  // extensions/browser/src/types.ts
  var extensionAPI = () => {
    const environment = globalThis;
    return environment.browser ?? environment.chrome;
  };

  // extensions/browser/src/background.ts
  var api = extensionAPI();
  var pending = /* @__PURE__ */ new Map();
  var TTL = 9e4;
  async function clear(tabId) {
    const candidate = pending.get(tabId);
    if (candidate) {
      candidate.password = "";
      candidate.username = "";
    }
    pending.delete(tabId);
    await api.action.setBadgeText({ tabId, text: "" }).catch(() => {
    });
  }
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== api.runtime.id) return;
    if (message?.action === "capture") {
      if (!acceptCapture(sender, api.runtime.id, message.candidate)) {
        respond({ ok: false });
        return;
      }
      const tabId = sender.tab.id;
      void clear(tabId).then(async () => {
        pending.set(tabId, message.candidate);
        await api.action.setBadgeBackgroundColor({ tabId, color: "#c8ed9f" });
        await api.action.setBadgeText({ tabId, text: "1" });
        setTimeout(() => {
          if (pending.get(tabId) === message.candidate) void clear(tabId);
        }, TTL);
        respond({ ok: true });
      });
      return true;
    }
    if (sender.tab || sender.frameId !== void 0 || !Number.isInteger(message?.tabId)) return;
    if (message.action === "clearCapture") {
      void clear(message.tabId).then(() => respond({ ok: true }));
      return true;
    }
    if (message.action === "pendingCapture") {
      void api.tabs.get(message.tabId).then(async (tab) => {
        const candidate = pending.get(message.tabId);
        if (!candidate || Date.now() - candidate.capturedAt > TTL || !safePageUrl(tab.url) || !matchesUrl(candidate.url, tab.url)) {
          await clear(message.tabId);
          respond({ ok: true, candidate: null });
          return;
        }
        respond({ ok: true, candidate });
      }).catch(() => respond({ ok: false }));
      return true;
    }
  });
  api.tabs.onRemoved.addListener((tabId) => {
    void clear(tabId);
  });
})();
//# sourceMappingURL=background.js.map
