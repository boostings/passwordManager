// Small fakes for chrome.* and the page DOM. No dependencies.

export const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
export const POPUP_URL = `chrome-extension://${EXT_ID}/popup.html`;
export const POPUP = Object.freeze({ id: EXT_ID, url: POPUP_URL });

/**
 * A fake chrome with one active tab. host(request) answers native messages; executeScript runs
 * the injected function through runInPage(func, args) so tests decide what the page looks like.
 */
export function fakeChrome({ tab = { id: 7, url: 'https://example.com/login' }, host, runInPage } = {}) {
  const sent = [];
  const injected = [];
  const listeners = [];
  const chrome = {
    sent,
    injected,
    listeners,
    runtime: {
      id: EXT_ID,
      getURL: (path) => `chrome-extension://${EXT_ID}/${path}`,
      async sendNativeMessage(name, request) {
        sent.push({ name, request: structuredClone(request) });
        return host(request);
      },
      onMessage: { addListener: (fn) => listeners.push(fn) },
    },
    tabs: {
      async query(q) {
        if (!q.active || !q.currentWindow) {
          throw new Error('unexpected query');
        }
        return tab ? [tab] : [];
      },
    },
    scripting: {
      async executeScript(details) {
        injected.push(details);
        return [{ frameId: 0, result: runInPage(details.func, details.args) }];
      },
    },
  };
  return chrome;
}

/** A host that approves everything, answering like pm-browser's Bridge. */
export function approvingHost(overrides = {}) {
  return (request) => {
    const base = { type: request.type, id: request.id };
    const answers = {
      lookup: { origin: request.origin, entries: [{ entry: ENTRY, title: 'Example', username: 'alice' }] },
      fill: { origin: request.origin, username: 'alice', password: 's3cret' },
      generate: { origin: request.origin, entry: ENTRY, password: 'Gen3rated!pw' },
      save: { entry: ENTRY },
    };
    return { ...base, ...answers[request.type], ...(overrides[request.type] ?? {}) };
  };
}

export const ENTRY = '00000000-0000-4000-8000-000000000001';

class FakeEvent {
  constructor(type, init) {
    this.type = type;
    this.bubbles = Boolean(init?.bubbles);
  }
}

/**
 * A fake input element. The page script reaches it only through the fake prototypes below, as it
 * would through Element.prototype in Chrome.
 *
 * hidden: checkVisibility() is false (display:none, visibility:hidden, opacity 0 on it or an
 * ancestor); size: its bounding box.
 */
export function input(type, {
  visible = true, hidden = false, size = { width: 120, height: 20 }, disabled = false, readOnly = false, form = null,
} = {}) {
  return {
    tagName: 'INPUT',
    type: type ?? 'text',
    value: '',
    disabled,
    readOnly,
    events: [],
    focused: false,
    visibilityChecks: [],
    __form: form,
    __attr: (name) => (name === 'type' && type !== null ? type : null),
    __visible(options) {
      this.visibilityChecks.push(options);
      return visible && !hidden;
    },
    __box: () => size,
    focus() {
      this.focused = true;
    },
    dispatchEvent(e) {
      this.events.push(e.type);
      return true;
    },
  };
}

/** A fake form whose inputs are returned by Element.prototype.querySelectorAll. */
export function form() {
  return { __inputs: [] };
}

/**
 * Runs func as Chrome would in a page: with window, location, document and the DOM prototypes
 * set to a fake page at origin, top-level unless framed is true.
 */
export function inPage({ origin, inputs, framed = false }) {
  return (func, args) => {
    const names = ['window', 'location', 'document', 'Event', 'Element', 'Document', 'HTMLInputElement'];
    const saved = Object.fromEntries(names.map((n) => [n, globalThis[n]]));
    const win = {};
    win.top = framed ? {} : win;
    const selectAll = (selector, list) => {
      if (selector !== 'input') {
        throw new Error(`unexpected selector ${selector}`);
      }
      return list;
    };
    function Element() {}
    Element.prototype.querySelectorAll = function (selector) {
      return selectAll(selector, this.__inputs);
    };
    Element.prototype.getAttribute = function (name) {
      return this.__attr(name);
    };
    Element.prototype.checkVisibility = function (options) {
      return this.__visible(options);
    };
    Element.prototype.getBoundingClientRect = function () {
      return this.__box();
    };
    function Document() {}
    Document.prototype.querySelectorAll = function (selector) {
      return selectAll(selector, inputs);
    };
    function HTMLInputElement() {}
    Object.defineProperty(HTMLInputElement.prototype, 'form', {
      get() {
        return this.__form;
      },
    });
    const doc = Object.create(Document.prototype);
    // A page could define these on its own nodes; the fill must not call them.
    doc.querySelectorAll = () => {
      throw new Error('document.querySelectorAll called directly');
    };
    Object.assign(globalThis, {
      window: win, location: { origin }, document: doc, Event: FakeEvent, Element, Document, HTMLInputElement,
    });
    try {
      // Re-create the function from its source, as executeScript does, so closures cannot leak in.
      const isolated = new Function(`return (${func.toString()})`)();
      return isolated(...args);
    } finally {
      Object.assign(globalThis, saved);
    }
  };
}
