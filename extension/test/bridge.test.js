// T-EXT-04: the background talks only to its popup, derives the origin from the tab, and fills
// only after the host approved exactly that origin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBackground, HOST } from '../src/bridge.js';
import { fillInPage } from '../src/fill.js';
import { approvingHost, ENTRY, EXT_ID, fakeChrome, inPage, input, POPUP } from './fakes.js';

const ORIGIN = 'https://example.com';
let counter = 0;
const newId = () => `req-${++counter}`;

function setup({ tab, host = approvingHost(), page } = {}) {
  const user = input('email');
  const secret = input('password');
  const runInPage = page ?? inPage({ origin: ORIGIN, inputs: [user, secret] });
  const chrome = fakeChrome({ tab, host, runInPage });
  return { chrome, user, secret, bg: createBackground(chrome, { newId }) };
}

test('fill: one native message for the tab origin, then a top-frame fill', async () => {
  const { chrome, bg, user, secret } = setup();
  const reply = await bg.onMessage({ kind: 'fill', entry: ENTRY }, POPUP);
  assert.deepEqual(reply, { ok: true, filled: true });
  assert.equal(chrome.sent.length, 1);
  assert.equal(chrome.sent[0].name, HOST);
  assert.deepEqual(chrome.sent[0].request, { type: 'fill', id: `req-${counter}`, origin: ORIGIN, entry: ENTRY });
  assert.equal(chrome.injected.length, 1);
  assert.deepEqual(chrome.injected[0].target, { tabId: 7, frameIds: [0] });
  assert.equal(chrome.injected[0].func, fillInPage);
  assert.equal(user.value, 'alice');
  assert.equal(secret.value, 's3cret');
  assert.ok(!JSON.stringify(reply).includes('s3cret'), 'the popup never receives the password');
});

test('fill: an origin the host did not approve is never injected', async () => {
  const { chrome, bg, secret } = setup({ host: approvingHost({ fill: { origin: 'https://a.example.com' } }) });
  assert.deepEqual(await bg.onMessage({ kind: 'fill', entry: ENTRY }, POPUP), { ok: false, code: 'ORIGIN_MISMATCH' });
  assert.equal(chrome.injected.length, 0);
  assert.equal(secret.value, '');
});

test('fill: the page navigated after approval, so the page script refuses', async () => {
  const user = input('email');
  const secret = input('password');
  const { bg } = setup({ page: inPage({ origin: 'https://evil.net', inputs: [user, secret] }) });
  assert.deepEqual(await bg.onMessage({ kind: 'fill', entry: ENTRY }, POPUP), { ok: false, code: 'ORIGIN_MISMATCH' });
  assert.equal(secret.value, '');
});

test('host refusals reach the popup as codes and nothing is filled', async () => {
  for (const code of ['DENIED', 'DENIED_LOCKED', 'DENIED_TIMEOUT', 'NOT_FOUND', 'BAD_ORIGIN']) {
    const { chrome, bg } = setup({ host: (r) => ({ type: 'error', id: r.id, code }) });
    assert.deepEqual(await bg.onMessage({ kind: 'fill', entry: ENTRY }, POPUP), { ok: false, code });
    assert.equal(chrome.injected.length, 0);
  }
  const odd = setup({ host: (r) => ({ type: 'error', id: r.id, code: '<b>x</b>' }) });
  assert.deepEqual(await odd.bg.onMessage({ kind: 'lookup' }, POPUP), { ok: false, code: 'BAD_REPLY' });
  const none = setup({ host: (r) => ({ type: 'error', id: r.id }) });
  assert.deepEqual(await none.bg.onMessage({ kind: 'lookup' }, POPUP), { ok: false, code: 'BAD_REPLY' });
});

test('a missing host, an empty reply or a reply to another request is refused', async () => {
  const missing = setup({ host: () => { throw new Error('Specified native messaging host not found.'); } });
  assert.deepEqual(await missing.bg.onMessage({ kind: 'lookup' }, POPUP), { ok: false, code: 'HOST_UNAVAILABLE' });
  for (const host of [() => undefined, () => 'text', (r) => ({ type: 'fill', id: 'other' }),
    (r) => ({ type: 'lookup', id: r.id, origin: ORIGIN, entries: 'x' }),
    (r) => ({ type: 'lookup', id: r.id, origin: ORIGIN, entries: [{ entry: 'nope', title: 't', username: 'u' }] }),
    (r) => ({ type: 'lookup', id: r.id, origin: ORIGIN, entries: [null] }),
    (r) => ({ type: 'lookup', id: r.id, origin: ORIGIN, entries: [{ entry: ENTRY, title: 1, username: 'u' }] }),
    (r) => ({ type: 'lookup', id: r.id, origin: ORIGIN, entries: [{ entry: ENTRY, title: 't', username: 2 }] })]) {
    const { bg } = setup({ host });
    assert.deepEqual(await bg.onMessage({ kind: 'lookup' }, POPUP), { ok: false, code: 'BAD_REPLY' });
  }
});

test('lookup returns metadata only', async () => {
  const { bg } = setup({
    host: approvingHost({ lookup: { entries: [{ entry: ENTRY, title: 'Example', username: 'alice', password: 'leak' }] } }),
  });
  assert.deepEqual(await bg.onMessage({ kind: 'lookup' }, POPUP), {
    ok: true, origin: ORIGIN, entries: [{ entry: ENTRY, title: 'Example', username: 'alice' }],
  });
  const moved = setup({ host: approvingHost({ lookup: { origin: 'http://example.com' } }) });
  assert.deepEqual(await moved.bg.onMessage({ kind: 'lookup' }, POPUP), { ok: false, code: 'ORIGIN_MISMATCH' });
});

test('generate asks the host to save the new login, then fills every password field', async () => {
  const fresh = input('password');
  const confirm = input('password');
  const { chrome, bg } = setup({ page: inPage({ origin: ORIGIN, inputs: [fresh, confirm] }) });
  const policy = { length: 20, lower: true, upper: true, digits: true, symbols: false };
  assert.deepEqual(await bg.onMessage({ kind: 'generate', username: 'dave', policy }, POPUP),
    { ok: true, filled: true, saved: true, entry: ENTRY });
  assert.deepEqual(chrome.sent[0].request,
    { type: 'generate', id: `req-${counter}`, origin: ORIGIN, username: 'dave', policy });
  assert.equal(fresh.value, 'Gen3rated!pw');
  assert.equal(confirm.value, 'Gen3rated!pw');
  for (const bad of [null, 'x', { ...policy, length: 7 }, { ...policy, length: 129 }, { ...policy, length: 8.5 },
    { ...policy, lower: 'yes' }, { length: 20, lower: false, upper: false, digits: false, symbols: false }]) {
    assert.deepEqual(await bg.onMessage({ kind: 'generate', username: '', policy: bad }, POPUP),
      { ok: false, code: 'BAD_REQUEST' });
  }
  assert.deepEqual(await bg.onMessage({ kind: 'generate', policy }, POPUP), { ok: false, code: 'BAD_REQUEST' });
});

test('a generated login that was saved but not filled is reported as saved', async () => {
  const policy = { length: 20, lower: true, upper: false, digits: false, symbols: false };
  const moved = setup({ host: approvingHost({ generate: { origin: 'https://evil.net' } }) });
  assert.deepEqual(await moved.bg.onMessage({ kind: 'generate', username: '', policy }, POPUP),
    { ok: false, code: 'ORIGIN_MISMATCH', saved: true, entry: ENTRY });
  assert.equal(moved.chrome.injected.length, 0);
  const noField = setup({ page: inPage({ origin: ORIGIN, inputs: [] }) });
  assert.deepEqual(await noField.bg.onMessage({ kind: 'generate', username: '', policy }, POPUP),
    { ok: false, code: 'NO_PASSWORD_FIELD', saved: true, entry: ENTRY });
  const throwing = setup({ page: () => { throw new TypeError('boom'); } });
  assert.deepEqual(await throwing.bg.onMessage({ kind: 'generate', username: '', policy }, POPUP),
    { ok: false, code: 'INTERNAL', saved: true, entry: ENTRY });
  const unsaved = setup({ host: approvingHost({ generate: { entry: undefined } }) });
  assert.deepEqual(await unsaved.bg.onMessage({ kind: 'generate', username: '', policy }, POPUP),
    { ok: false, code: 'BAD_REPLY' });
  assert.equal(unsaved.chrome.injected.length, 0, 'never fill a password the host did not confirm it stored');
});

test('a host that went away mid-request is reported, not silently dropped', async () => {
  for (const message of ['Native host has exited.', 'Error when communicating with the native messaging host.', undefined]) {
    const { bg } = setup({ host: () => { throw message === undefined ? 'odd' : new Error(message); } });
    assert.deepEqual(await bg.onMessage({ kind: 'lookup' }, POPUP), { ok: false, code: 'HOST_DISCONNECTED' }, message);
  }
  const forbidden = setup({ host: () => { throw new Error('Access to the specified native messaging host is forbidden.'); } });
  assert.deepEqual(await forbidden.bg.onMessage({ kind: 'lookup' }, POPUP), { ok: false, code: 'HOST_UNAVAILABLE' });
});

test('save sends the tab origin and returns only the new id', async () => {
  const { chrome, bg } = setup();
  assert.deepEqual(await bg.onMessage({ kind: 'save', username: 'carol', password: 'n3w' }, POPUP),
    { ok: true, saved: true, entry: ENTRY });
  assert.deepEqual(chrome.sent[0].request, { type: 'save', id: `req-${counter}`, origin: ORIGIN, username: 'carol', password: 'n3w' });
  assert.deepEqual(await bg.onMessage({ kind: 'save', username: 'carol', password: '' }, POPUP), { ok: false, code: 'BAD_REQUEST' });
  assert.deepEqual(await bg.onMessage({ kind: 'save', username: 5, password: 'x' }, POPUP), { ok: false, code: 'BAD_REQUEST' });
  assert.deepEqual(await bg.onMessage({ kind: 'save', username: 'u', password: 'x'.repeat(4097) }, POPUP),
    { ok: false, code: 'BAD_REQUEST' });
  const bad = setup({ host: approvingHost({ save: { entry: 'nope' } }) });
  assert.deepEqual(await bad.bg.onMessage({ kind: 'save', username: 'u', password: 'x' }, POPUP), { ok: false, code: 'BAD_REPLY' });
});

test('only the extension popup may ask', async () => {
  const { chrome, bg } = setup();
  for (const sender of [undefined, null, {}, { id: 'ponmlkjihgfedcbaponmlkjihgfedcba', url: POPUP.url },
    { id: EXT_ID, url: POPUP.url, tab: { id: 3 } }, { id: EXT_ID, url: `chrome-extension://${EXT_ID}/other.html` },
    { id: EXT_ID, url: 'https://example.com/', tab: { id: 7 } }]) {
    assert.deepEqual(await bg.onMessage({ kind: 'fill', entry: ENTRY }, sender), { ok: false, code: 'FORBIDDEN' });
  }
  assert.equal(chrome.sent.length, 0);
});

test('unknown or malformed popup messages are refused', async () => {
  const { chrome, bg } = setup();
  for (const msg of [null, 'fill', {}, { kind: 'toString' }, { kind: '__proto__' }, { kind: 'reveal' },
    { kind: 'fill' }, { kind: 'fill', entry: 'not-a-uuid' }]) {
    assert.deepEqual(await bg.onMessage(msg, POPUP), { ok: false, code: 'BAD_REQUEST' });
  }
  assert.equal(chrome.sent.length, 0);
});

test('non-web tabs and missing tabs are refused before the host is asked', async () => {
  for (const tab of [null, { id: 1, url: 'chrome://settings' }, { id: 1, url: 'file:///etc/passwd' },
    { id: 1, url: 'javascript:alert(1)' }, { id: 1 }, { url: ORIGIN }, { id: 1, url: 'not a url' }]) {
    const { chrome, bg } = setup({ tab });
    const reply = await bg.onMessage({ kind: 'lookup' }, POPUP);
    assert.equal(reply.ok, false);
    assert.ok(['NO_TAB', 'NOT_A_WEB_PAGE'].includes(reply.code), reply.code);
    assert.equal(chrome.sent.length, 0);
  }
});

test('host fill replies are type-checked before injection', async () => {
  for (const fill of [{ password: '' }, { password: 7 }, { username: null }]) {
    const { chrome, bg } = setup({ host: approvingHost({ fill }) });
    assert.deepEqual(await bg.onMessage({ kind: 'fill', entry: ENTRY }, POPUP), { ok: false, code: 'BAD_REPLY' });
    assert.equal(chrome.injected.length, 0);
  }
});

test('injection results are checked', async () => {
  for (const [result, code] of [[undefined, 'NOT_FILLED'], [{ filled: false }, 'NOT_FILLED'],
    [{ filled: false, reason: 'NO_PASSWORD_FIELD' }, 'NO_PASSWORD_FIELD'], [{ filled: false, reason: '<x>' }, 'NOT_FILLED']]) {
    const { bg } = setup({ page: () => result });
    assert.deepEqual(await bg.onMessage({ kind: 'fill', entry: ENTRY }, POPUP), { ok: false, code });
  }
  const throwing = setup({ page: () => { throw new TypeError('boom'); } });
  assert.deepEqual(await throwing.bg.onMessage({ kind: 'fill', entry: ENTRY }, POPUP), { ok: false, code: 'INTERNAL' });
});

test('install registers one asynchronous listener', async () => {
  const { chrome, bg } = setup();
  bg.install();
  assert.equal(chrome.listeners.length, 1);
  const answer = await new Promise((resolve) => {
    assert.equal(chrome.listeners[0]({ kind: 'lookup' }, POPUP, resolve), true);
  });
  assert.equal(answer.ok, true);
});
