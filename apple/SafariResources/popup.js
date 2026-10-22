"use strict";
(() => {
  // extensions/browser/src/types.ts
  var extensionAPI = () => {
    const environment = globalThis;
    return environment.browser ?? environment.chrome;
  };

  // extensions/browser/src/matching.ts
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

  // extensions/browser/src/popup.ts
  var api = extensionAPI();
  var $ = (id) => document.getElementById(id);
  var tabId;
  var activeUrl = "";
  var items = [];
  var candidate = null;
  var busy = false;
  function status(message, kind = "neutral") {
    $("status").textContent = message;
    $("status").dataset.kind = kind;
  }
  async function native(action, rest = {}) {
    const reply = await api.runtime.sendNativeMessage("com.john.jjvault.safari", { action, url: activeUrl, ...rest });
    if (!reply?.ok) throw new Error(reply?.error || "JJ Vault did not respond.");
    return reply.result;
  }
  async function checkPage() {
    if (tabId === void 0) throw new Error("Open a website first.");
    const tab = await api.tabs.get(tabId);
    if (!tab.url || !sameDocument(activeUrl, tab.url)) throw new Error("The page changed. Reopen JJ Vault to continue.");
  }
  var labels = { login: "Login", password: "Password", identity: "Identity", creditCard: "Card" };
  var symbols = { login: "\u2197", password: "\u2733", identity: "\u25CE", creditCard: "\u25B0" };
  function render() {
    const query = $("search").value.toLowerCase();
    const type = $("typeFilter").value;
    const matches = items.filter((item) => (!type || item.type === type) && `${item.title} ${item.username ?? ""}`.toLowerCase().includes(query));
    const list = $("items");
    list.replaceChildren();
    $("count").textContent = `${matches.length} ${matches.length === 1 ? "item" : "items"}`;
    if (!matches.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = query ? "No items match your search." : "No matching items. Check browser access in JJ Vault.";
      list.append(empty);
      return;
    }
    for (const item of matches) {
      const button = document.createElement("button");
      button.className = "item";
      button.type = "button";
      button.setAttribute("aria-label", `Fill ${item.title}, ${labels[item.type] ?? item.type}`);
      const icon = document.createElement("span");
      icon.className = "itemIcon";
      icon.textContent = symbols[item.type] ?? "\u25C7";
      const info = document.createElement("span");
      info.className = "itemInfo";
      const title = document.createElement("strong");
      title.textContent = item.title;
      const detail = document.createElement("span");
      detail.textContent = item.username || labels[item.type] || item.type;
      info.append(title, detail);
      const fill = document.createElement("span");
      fill.className = "fillLabel";
      fill.textContent = "Fill";
      button.append(icon, info, fill);
      button.addEventListener("click", () => void fillItem(item.id));
      list.append(button);
    }
  }
  async function fillItem(id) {
    if (busy) return;
    busy = true;
    let secret;
    try {
      await checkPage();
      status("Requesting this item from JJ Vault\u2026");
      secret = await native("get", { id });
      await checkPage();
      const reply = await api.tabs.sendMessage(tabId, { action: "fill", expectedUrl: activeUrl, item: secret }, { frameId: 0 });
      if (!reply?.ok) throw new Error(reply?.error || "Reload this page, then try filling again.");
      status(reply.filled ? `Filled ${reply.filled} ${reply.filled === 1 ? "field" : "fields"}. You can review and submit.` : "No compatible visible fields were found.", reply.filled ? "success" : "neutral");
    } catch (error) {
      status(cleanError(error), "error");
    } finally {
      if (secret) {
        secret.password = "";
        secret.username = "";
        secret.totp = "";
        secret.fields?.forEach((field) => {
          field.value = "";
        });
      }
      secret = void 0;
      busy = false;
    }
  }
  function cleanError(error) {
    const message = error instanceof Error ? error.message : "JJ Vault could not complete the request.";
    if (/native messaging host not found|host.*not found|not.*registered|specified native messaging host/i.test(message)) return "Pair this extension with the Mac app using the setup steps below.";
    if (/not.*connect|connection refused|exited|disconnected|failed to connect/i.test(message)) return "Open JJ Vault on your Mac, unlock it, and try again.";
    if (/locked/i.test(message)) return "Vault is locked. Unlock JJ Vault on your Mac, then refresh.";
    return message.slice(0, 240);
  }
  function showCandidate() {
    $("capture").hidden = !candidate;
    if (!candidate) return;
    $("saveTitle").value = candidate.title || new URL(candidate.url).hostname;
    $("saveUser").textContent = candidate.username || "No username";
    const select = $("saveTarget");
    select.replaceChildren();
    const create = document.createElement("option");
    create.value = "";
    create.textContent = "Save as a new login";
    select.append(create);
    for (const item of items.filter((item2) => item2.type === "login")) {
      const option = document.createElement("option");
      option.value = item.id;
      option.textContent = `Update ${item.title}${item.username ? ` (${item.username})` : ""}`;
      select.append(option);
    }
  }
  async function saveCandidate(event) {
    event.preventDefault();
    if (!candidate || busy) return;
    busy = true;
    try {
      await checkPage();
      if (Date.now() - candidate.capturedAt > 9e4) throw new Error("The save offer expired. Submit the login again to capture it.");
      const title = $("saveTitle").value.trim();
      if (!title) throw new Error("Give this login a name.");
      const id = $("saveTarget").value;
      await native("save", { item: { ...id ? { id } : {}, type: "login", title, username: candidate.username, password: candidate.password, urls: [candidate.url] } });
      await clearCandidate();
      status(id ? "Password updated in JJ Vault." : "Login saved in JJ Vault.", "success");
      items = await native("list");
      render();
    } catch (error) {
      status(cleanError(error), "error");
    } finally {
      busy = false;
    }
  }
  async function clearCandidate() {
    if (candidate) {
      candidate.password = "";
      candidate.username = "";
    }
    candidate = null;
    $("capture").hidden = true;
    if (tabId !== void 0) await api.runtime.sendMessage({ action: "clearCapture", tabId });
  }
  async function load() {
    try {
      $("connection").textContent = "Connecting";
      const [tab] = await api.tabs.query({ active: true, currentWindow: true });
      if (!tab || tab.id === void 0 || !safePageUrl(tab.url)) throw new Error("Open an HTTPS website to use autofill.");
      tabId = tab.id;
      activeUrl = tab.url;
      $("website").textContent = new URL(activeUrl).hostname;
      items = await native("list");
      if (!Array.isArray(items)) throw new Error("The vault returned an invalid response.");
      await checkPage();
      $("connection").textContent = "Connected";
      $("connection").dataset.connected = "true";
      status("Select an item to fill this website.");
      render();
      const pending = await api.runtime.sendMessage({ action: "pendingCapture", tabId });
      candidate = pending?.candidate ?? null;
      showCandidate();
    } catch (error) {
      $("connection").textContent = "Unavailable";
      $("connection").dataset.connected = "false";
      status(cleanError(error), "error");
      $("items").replaceChildren();
    }
  }
  $("search").addEventListener("input", render);
  $("typeFilter").addEventListener("change", render);
  $("refresh").addEventListener("click", () => void load());
  $("saveForm").addEventListener("submit", (event) => void saveCandidate(event));
  $("dismiss").addEventListener("click", () => void clearCandidate());
  $("extensionId").textContent = api.runtime.id;
  window.addEventListener("unload", () => {
    if (candidate) {
      candidate.password = "";
      candidate.username = "";
    }
    items = [];
  });
  void load();
})();
//# sourceMappingURL=popup.js.map
