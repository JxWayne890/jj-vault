"use strict";
(() => {
  // extensions/browser/src/types.ts
  var extensionAPI = () => {
    const environment = globalThis;
    return environment.browser ?? environment.chrome;
  };

  // extensions/browser/src/fields.ts
  var key = (value) => value.toLowerCase().replace(/[^a-z0-9]/g, "");
  var aliases = {
    "cc-name": ["cardholder", "cardholdername", "nameoncard", "ccname"],
    "cc-number": ["cardnumber", "creditcardnumber", "ccnumber", "number"],
    "cc-exp": ["expiry", "expirydate", "expiration", "expirationdate", "ccexp"],
    "cc-exp-month": ["expmonth", "expirationmonth", "month"],
    "cc-exp-year": ["expyear", "expirationyear", "year"],
    "cc-csc": ["cvv", "cvc", "securitycode", "cccsc"],
    "name": ["fullname", "name"],
    "given-name": ["firstname", "givenname"],
    "family-name": ["lastname", "surname", "familyname"],
    "additional-name": ["middlename", "additionalname"],
    "email": ["email", "emailaddress"],
    "tel": ["phone", "telephone", "mobile", "phonenumber"],
    "organization": ["company", "organization", "companyname"],
    "street-address": ["address", "streetaddress", "street"],
    "address-line1": ["addressline1", "address1", "streetaddress", "street"],
    "address-line2": ["addressline2", "address2", "apartment", "suite"],
    "address-level2": ["city", "town", "addresslevel2"],
    "address-level1": ["state", "province", "region", "addresslevel1"],
    "postal-code": ["zip", "zipcode", "postalcode", "postcode"],
    "country": ["country", "countrycode"]
  };
  function customValue(item, token) {
    const keys = [key(token), ...aliases[token] ?? []];
    return item.fields?.find((field) => keys.includes(key(field.label)))?.value;
  }
  function fieldValue(item, descriptor2) {
    const tokens = descriptor2.autocomplete.toLowerCase().split(/\s+/);
    if (tokens.includes("off")) return void 0;
    const autocomplete = tokens.find((token2) => token2 === "one-time-code" || token2 === "username" || token2.includes("password") || token2 in aliases);
    const names = [descriptor2.name, descriptor2.id, descriptor2.label].map(key);
    const isLogin = item.type === "login" || item.type === "password";
    if (isLogin) {
      if (autocomplete === "new-password") return void 0;
      if (autocomplete === "one-time-code" || names.some((name) => /^(otp|totp|onetimecode|verificationcode|authenticatorcode)$/.test(name))) return item.totp;
      if (descriptor2.type === "password" || autocomplete === "current-password") return item.password;
      if (autocomplete === "username" || autocomplete === "email" || descriptor2.type === "email" || names.some((name) => /^(username|user|login|email|emailaddress|loginname)$/.test(name))) return item.username;
      return void 0;
    }
    if (descriptor2.type === "password" || autocomplete?.includes("password") || autocomplete === "one-time-code") return void 0;
    const isCard = item.type === "creditCard";
    if (!isCard && item.type !== "identity") return void 0;
    let token = autocomplete;
    if (!token) token = Object.keys(aliases).find((candidate) => candidate.startsWith("cc-") === isCard && names.some((name) => aliases[candidate].includes(name)));
    if (!token || token.startsWith("cc-") !== isCard) return void 0;
    if (isCard && (token === "cc-exp-month" || token === "cc-exp-year")) {
      const direct = customValue(item, token);
      if (direct) return direct;
      const expiry = customValue(item, "cc-exp");
      const match = expiry?.match(/^(\d{1,2})\s*\/\s*(\d{2}|\d{4})$/);
      if (match) return token === "cc-exp-month" ? match[1].padStart(2, "0") : match[2].length === 2 ? `20${match[2]}` : match[2];
    }
    return customValue(item, token);
  }

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

  // extensions/browser/src/content.ts
  var api = extensionAPI();
  var topFrame = window.top === window.self;
  var MAX_CAPTURE_AGE = 9e4;
  function visible(element) {
    if (element.disabled || "readOnly" in element && element.readOnly || element.getAttribute("aria-hidden") === "true") return false;
    if (element instanceof HTMLInputElement && ["hidden", "submit", "button", "checkbox", "radio", "file"].includes(element.type)) return false;
    const style = getComputedStyle(element);
    return element.getClientRects().length > 0 && style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) !== 0;
  }
  function descriptor(element) {
    return { autocomplete: element.autocomplete, type: element instanceof HTMLInputElement ? element.type : element.tagName.toLowerCase(), name: element.name, id: element.id, label: Array.from(element.labels ?? []).map((label) => label.textContent ?? "").join(" ") };
  }
  function safeForm(form) {
    if (!form) return true;
    try {
      return new URL(form.action || location.href, location.href).origin === location.origin;
    } catch {
      return false;
    }
  }
  function insert(element, value) {
    if (element instanceof HTMLSelectElement) {
      const option = Array.from(element.options).find((option2) => option2.value.toLowerCase() === value.toLowerCase() || option2.text.toLowerCase() === value.toLowerCase() || /^\d+$/.test(value) && Number(option2.value) === Number(value));
      if (!option) return false;
      element.value = option.value;
    } else {
      const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
      if (!setter) return false;
      setter.call(element, value);
    }
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }
  function fillItem(item, expectedUrl) {
    if (!topFrame || !sameDocument(expectedUrl, location.href)) throw new Error("The page changed. Open JJ Vault again.");
    if (!item || !["login", "password", "identity", "creditCard"].includes(item.type)) throw new Error("This item cannot be filled.");
    if ((item.type === "login" || item.type === "password") && !item.urls?.some((url) => matchesUrl(url, location.href))) throw new Error("This login does not match this website.");
    if (item.urls?.length && !item.urls.some((url) => matchesUrl(url, location.href))) throw new Error("This item does not match this website.");
    const controls = Array.from(document.querySelectorAll("input,select,textarea")).filter(visible).filter((element) => safeForm(element.form));
    const matches = controls.map((element) => ({ element, value: fieldValue(item, descriptor(element)) })).filter((match) => match.value !== void 0);
    const focused = matches.find((match) => match.element === document.activeElement);
    const password = matches.find((match) => match.element instanceof HTMLInputElement && match.element.type === "password");
    const form = (focused ?? password ?? matches[0])?.element.form;
    if (form === void 0) return { filled: 0 };
    let filled = 0;
    for (const match of matches) {
      if (match.element.form !== form || !visible(match.element) || !safeForm(match.element.form) || !sameDocument(expectedUrl, location.href)) continue;
      if (insert(match.element, match.value)) filled++;
    }
    return { filled };
  }
  if (topFrame) {
    api.runtime.onMessage.addListener((message, sender, respond) => {
      if (sender.id !== api.runtime.id) return;
      if (message?.action !== "fill" || typeof message.expectedUrl !== "string") return;
      try {
        respond({ ok: true, ...fillItem(message.item, message.expectedUrl) });
      } catch (error) {
        respond({ ok: false, error: error instanceof Error ? error.message : "Autofill failed." });
      }
    });
    document.addEventListener("submit", (event) => {
      if (!event.isTrusted || !safePageUrl(location.href) || !(event.target instanceof HTMLFormElement) || !safeForm(event.target)) return;
      const fields = Array.from(event.target.querySelectorAll("input")).filter(visible);
      const passwords = fields.filter((field) => field.type === "password" && field.value);
      const fresh = passwords.filter((field) => field.autocomplete === "new-password");
      const passwordField = fresh[0] ?? passwords[0];
      if (!passwordField || passwordField.value.length > 4096 || fresh.length > 1 && fresh.some((field) => field.value !== passwordField.value)) return;
      const userField = fields.find((field) => field.autocomplete === "username") ?? fields.find((field) => field.type === "email") ?? fields.find((field) => /^(user(name)?|login|email)$/i.test(field.name || field.id));
      const candidate = { url: location.href, title: document.title.slice(0, 512) || location.hostname, username: (userField?.value ?? "").slice(0, 4096), password: passwordField.value, capturedAt: Date.now() };
      api.runtime.sendMessage({ action: "capture", candidate }).catch(() => {
      });
      setTimeout(() => {
        candidate.password = "";
        candidate.username = "";
      }, MAX_CAPTURE_AGE);
    }, { capture: true });
  }
})();
//# sourceMappingURL=content.js.map
