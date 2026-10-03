// Background logic: popup <-> native host <-> page (ADR 0014 §7).
//
// Kept free of globals so the tests can pass fakes for chrome.*. The background accepts messages
// only from its own popup, derives the page origin itself from the active tab (never from the
// popup), sends one native message per request, and fills only into the top-level frame of the
// same tab after checking the host's approved origin equals the tab's origin.

import { fillInPage } from './fill.js';

/** Name of the native messaging host (extension/native-host/pm.browser.json.template). */
export const HOST = 'pm.browser';

const WEB_SCHEMES = new Set(['http:', 'https:']);
const CODE = /^[A-Z][A-Z_]{0,31}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_TEXT = 4096;

/** A refusal with a short code the popup can show, plus non-secret facts it must know. */
export class BridgeError extends Error {
  constructor(code, detail = {}) {
    super(code);
    this.code = code;
    this.detail = detail;
  }
}

// What Chrome reports when it cannot start the host at all, as opposed to a host that started
// and then went away (crashed, was killed, or this service worker was stopped mid-request).
const NOT_INSTALLED = /not found|forbidden/i;

function text(value, min, code = 'BAD_REQUEST') {
  if (typeof value !== 'string' || value.length < min || value.length > MAX_TEXT) {
    throw new BridgeError(code);
  }
  return value;
}

function policy(value) {
  if (!value || typeof value !== 'object') {
    throw new BridgeError('BAD_REQUEST');
  }
  const { length, lower, upper, digits, symbols } = value;
  const flags = [lower, upper, digits, symbols];
  if (!Number.isInteger(length) || length < 8 || length > 128
      || !flags.every((f) => typeof f === 'boolean') || !flags.some(Boolean)) {
    throw new BridgeError('BAD_REQUEST');
  }
  return { length, lower, upper, digits, symbols };
}

/**
 * @param {object} chrome the extension API (or a fake)
 * @param {{newId?: () => string, fill?: Function}} [options]
 */
export function createBackground(chrome, { newId = () => crypto.randomUUID(), fill = fillInPage } = {}) {
  async function activeTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !Number.isInteger(tab.id) || typeof tab.url !== 'string') {
      throw new BridgeError('NO_TAB');
    }
    let url;
    try {
      url = new URL(tab.url);
    } catch {
      throw new BridgeError('NO_TAB');
    }
    if (!WEB_SCHEMES.has(url.protocol)) {
      throw new BridgeError('NOT_A_WEB_PAGE');
    }
    return { tabId: tab.id, origin: url.origin };
  }

  async function ask(request) {
    let reply;
    try {
      reply = await chrome.runtime.sendNativeMessage(HOST, request);
    } catch (e) {
      throw new BridgeError(NOT_INSTALLED.test(String(e?.message)) ? 'HOST_UNAVAILABLE' : 'HOST_DISCONNECTED');
    }
    if (!reply || typeof reply !== 'object') {
      throw new BridgeError('BAD_REPLY');
    }
    if (reply.type === 'error') {
      throw new BridgeError(typeof reply.code === 'string' && CODE.test(reply.code) ? reply.code : 'BAD_REPLY');
    }
    if (reply.type !== request.type || reply.id !== request.id) {
      throw new BridgeError('BAD_REPLY');
    }
    return reply;
  }

  /** The host must have approved exactly the tab's origin. */
  function sameOrigin(reply, origin) {
    if (reply.origin !== origin) {
      throw new BridgeError('ORIGIN_MISMATCH');
    }
  }

  async function inject(tabId, args) {
    const results = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: fill,
      args,
    });
    const outcome = results?.[0]?.result;
    if (!outcome || outcome.filled !== true) {
      throw new BridgeError(outcome && CODE.test(outcome.reason ?? '') ? outcome.reason : 'NOT_FILLED');
    }
  }

  const handlers = {
    async lookup() {
      const { origin } = await activeTab();
      const reply = await ask({ type: 'lookup', id: newId(), origin });
      sameOrigin(reply, origin);
      if (!Array.isArray(reply.entries)) {
        throw new BridgeError('BAD_REPLY');
      }
      const entries = reply.entries.map((e) => {
        if (!e || !UUID.test(e.entry) || typeof e.title !== 'string' || typeof e.username !== 'string') {
          throw new BridgeError('BAD_REPLY');
        }
        return { entry: e.entry, title: e.title, username: e.username };
      });
      return { origin, entries };
    },

    async fill(msg) {
      if (typeof msg.entry !== 'string' || !UUID.test(msg.entry)) {
        throw new BridgeError('BAD_REQUEST');
      }
      const { tabId, origin } = await activeTab();
      const reply = await ask({ type: 'fill', id: newId(), origin, entry: msg.entry });
      sameOrigin(reply, origin);
      await inject(tabId, [reply.origin, text(reply.username, 0, 'BAD_REPLY'), text(reply.password, 1, 'BAD_REPLY'), false]);
      return { filled: true };
    },

    // The host stores the generated password as a new login before it answers, so a fill that
    // fails afterwards loses nothing: the popup is told the login was saved.
    async generate(msg) {
      const wanted = policy(msg.policy);
      const username = text(msg.username, 0);
      const { tabId, origin } = await activeTab();
      const reply = await ask({ type: 'generate', id: newId(), origin, username, policy: wanted });
      if (!UUID.test(reply.entry)) {
        throw new BridgeError('BAD_REPLY');
      }
      const saved = { saved: true, entry: reply.entry };
      try {
        sameOrigin(reply, origin);
        await inject(tabId, [reply.origin, null, text(reply.password, 1, 'BAD_REPLY'), true]);
      } catch (e) {
        throw new BridgeError(e instanceof BridgeError ? e.code : 'INTERNAL', saved);
      }
      return { filled: true, ...saved };
    },

    async save(msg) {
      const username = text(msg.username, 0);
      const secret = text(msg.password, 1);
      const { origin } = await activeTab();
      const reply = await ask({ type: 'save', id: newId(), origin, username, password: secret });
      if (!UUID.test(reply.entry)) {
        throw new BridgeError('BAD_REPLY');
      }
      return { saved: true, entry: reply.entry };
    },
  };

  function fromPopup(sender) {
    return Boolean(sender)
      && sender.id === chrome.runtime.id
      && sender.tab === undefined
      && sender.url === chrome.runtime.getURL('popup.html');
  }

  /** Answers one popup message; never returns a password to the popup. */
  async function onMessage(msg, sender) {
    if (!fromPopup(sender)) {
      return { ok: false, code: 'FORBIDDEN' };
    }
    if (!msg || typeof msg !== 'object' || !Object.hasOwn(handlers, msg.kind)) {
      return { ok: false, code: 'BAD_REQUEST' };
    }
    try {
      return { ok: true, ...(await handlers[msg.kind](msg)) };
    } catch (e) {
      return e instanceof BridgeError ? { ok: false, code: e.code, ...e.detail } : { ok: false, code: 'INTERNAL' };
    }
  }

  return {
    onMessage,
    install() {
      chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        onMessage(msg, sender).then(sendResponse);
        return true; // the response is sent asynchronously
      });
    },
  };
}
