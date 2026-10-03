// The popup renders host data as text and never handles a stored password.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describe as describeCode, renderEntries, start } from '../src/popup.js';
import { ENTRY } from './fakes.js';

class Node {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.listeners = {};
    this.textContent = '';
    this.value = '';
    this.checked = false;
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
}

function fakeDocument() {
  const byId = {};
  for (const id of ['status', 'origin', 'entries', 'generate', 'save', 'gen-username', 'gen-length', 'gen-lower', 'gen-upper',
    'gen-digits', 'gen-symbols', 'save-username', 'save-password']) {
    byId[id] = new Node(id);
  }
  return { byId, createElement: (tag) => new Node(tag), getElementById: (id) => byId[id] };
}

test('entries are rendered with textContent only', () => {
  const doc = fakeDocument();
  const picked = [];
  renderEntries(doc, doc.byId.entries, [{ entry: ENTRY, title: '<img src=x onerror=alert(1)>', username: 'alice' }],
    (e) => picked.push(e));
  const button = doc.byId.entries.children[0].children[0];
  assert.equal(button.tagName, 'button');
  assert.equal(button.textContent, '<img src=x onerror=alert(1)>');
  assert.equal(button.children[0].textContent, 'alice');
  button.listeners.click();
  assert.deepEqual(picked, [ENTRY]);
  renderEntries(doc, doc.byId.entries, [], () => {});
  assert.equal(doc.byId.entries.children[0].textContent, 'No logins for this site.');
});

test('refusal codes become sentences', () => {
  assert.equal(describeCode('DENIED_LOCKED'), 'pm is locked. Unlock it and try again.');
  assert.equal(describeCode('WEIRD'), 'Refused (WEIRD).');
});

test('start lists logins, fills on click, generates and saves through the background', async () => {
  const doc = fakeDocument();
  const sent = [];
  const replies = {
    lookup: { ok: true, origin: 'https://example.com', entries: [{ entry: ENTRY, title: 'Example', username: 'alice' }] },
    fill: { ok: true, filled: true },
    generate: { ok: true, filled: true, saved: true, entry: ENTRY },
    save: { ok: true, saved: true, entry: ENTRY },
  };
  const chrome = { runtime: { sendMessage: async (msg) => { sent.push(msg); return replies[msg.kind]; } } };
  await start(chrome, doc);
  assert.equal(doc.byId.origin.textContent, 'https://example.com');

  await doc.byId.entries.children[0].children[0].listeners.click();
  assert.deepEqual(sent.at(-1), { kind: 'fill', entry: ENTRY });
  assert.equal(doc.byId.status.textContent, 'Filled.');

  doc.byId['gen-username'].value = 'dave';
  doc.byId['gen-length'].value = '24';
  doc.byId['gen-lower'].checked = true;
  let prevented = 0;
  await doc.byId.generate.listeners.submit({ preventDefault: () => prevented++ });
  assert.deepEqual(sent.at(-1), {
    kind: 'generate', username: 'dave', policy: { length: 24, lower: true, upper: false, digits: false, symbols: false },
  });
  assert.equal(doc.byId.status.textContent, 'New password saved in pm and filled.');

  replies.generate = { ok: false, code: 'NO_PASSWORD_FIELD', saved: true, entry: ENTRY };
  await doc.byId.generate.listeners.submit({ preventDefault: () => prevented++ });
  assert.equal(doc.byId.status.textContent,
    'Saved in pm as a new login, but not filled: No password field on this page.');
  replies.generate = { ok: false, code: 'DENIED' };
  await doc.byId.generate.listeners.submit({ preventDefault: () => prevented++ });
  assert.equal(doc.byId.status.textContent, 'Denied in pm.');

  doc.byId['save-username'].value = 'carol';
  doc.byId['save-password'].value = 'n3w';
  await doc.byId.save.listeners.submit({ preventDefault: () => prevented++ });
  assert.deepEqual(sent.at(-1), { kind: 'save', username: 'carol', password: 'n3w' });
  assert.equal(doc.byId['save-password'].value, '', 'the typed password is cleared');
  assert.equal(doc.byId.status.textContent, 'Saved.');
  assert.equal(prevented, 4);
});

test('a background that stopped mid-request is reported', async () => {
  for (const sendMessage of [async () => { throw new Error('The message port closed before a response was received.'); },
    async () => undefined]) {
    const doc = fakeDocument();
    await start({ runtime: { sendMessage } }, doc);
    assert.equal(doc.byId.status.textContent,
      'The request was interrupted before pm answered. Check pm, then try again.');
  }
});

test('a failed lookup shows the reason and renders nothing', async () => {
  const doc = fakeDocument();
  const chrome = { runtime: { sendMessage: async () => ({ ok: false, code: 'HOST_UNAVAILABLE' }) } };
  await start(chrome, doc);
  assert.equal(doc.byId.status.textContent, 'pm is not installed or not running.');
  assert.equal(doc.byId.entries.children.length, 0);
});
