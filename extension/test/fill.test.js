// T-EXT-04 / SR-309: the injected fill runs only in the top frame of the approved origin, and
// writes only into fields the user can see.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fillInPage } from '../src/fill.js';
import { form, inPage, input } from './fakes.js';

const ORIGIN = 'https://example.com';

function loginPage(origin = ORIGIN, framed = false) {
  const login = form();
  const user = input('email', { form: login });
  const secret = input('password', { form: login });
  login.__inputs = [input('hidden', { form: login, visible: false }), user, secret];
  return { login, user, secret, run: inPage({ origin, inputs: login.__inputs, framed }) };
}

test('fills username and password on the approved top-level origin', () => {
  const page = loginPage();
  assert.deepEqual(page.run(fillInPage, [ORIGIN, 'alice', 's3cret', false]), { filled: true });
  assert.equal(page.user.value, 'alice');
  assert.equal(page.secret.value, 's3cret');
  assert.deepEqual(page.secret.events, ['input', 'change']);
  assert.ok(page.secret.focused);
  assert.deepEqual(page.secret.visibilityChecks[0],
    { opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true });
});

test('refuses any other origin and writes nothing', () => {
  for (const other of ['https://a.example.com', 'http://example.com', 'https://example.com:8443',
    'https://xn--xample-2of.com', 'null']) {
    const page = loginPage(other);
    assert.deepEqual(page.run(fillInPage, [ORIGIN, 'alice', 's3cret', false]),
      { filled: false, reason: 'ORIGIN_MISMATCH' }, other);
    assert.equal(page.secret.value, '');
    assert.equal(page.user.value, '');
  }
});

test('refuses inside a frame even of the same origin', () => {
  const page = loginPage(ORIGIN, true);
  assert.deepEqual(page.run(fillInPage, [ORIGIN, 'alice', 's3cret', false]),
    { filled: false, reason: 'ORIGIN_MISMATCH' });
  assert.equal(page.secret.value, '');
});

test('hidden, transparent, zero-sized, disabled and read-only fields are never filled', () => {
  const inputs = [
    input('text'),
    input('password', { visible: false }),
    input('password', { hidden: true }), // visibility:hidden or opacity 0, on it or an ancestor
    input('password', { size: { width: 0, height: 20 } }),
    input('password', { size: { width: 120, height: 0 } }),
    input('password', { disabled: true }),
    input('password', { readOnly: true }),
  ];
  const run = inPage({ origin: ORIGIN, inputs });
  assert.deepEqual(run(fillInPage, [ORIGIN, 'alice', 's3cret', true]), { filled: false, reason: 'NO_PASSWORD_FIELD' });
  assert.ok(inputs.every((i) => i.value === ''));
});

test('a hidden username decoy is skipped for the visible field before it', () => {
  const real = input('text');
  const decoy = input('text', { hidden: true });
  const secret = input('password');
  const run = inPage({ origin: ORIGIN, inputs: [real, decoy, secret] });
  run(fillInPage, [ORIGIN, 'bob', 'pw', false]);
  assert.equal(real.value, 'bob');
  assert.equal(decoy.value, '');
});

test('a form control named querySelectorAll cannot redirect the username', () => {
  const page = loginPage();
  const decoy = input('text');
  // <input name="querySelectorAll"> makes form.querySelectorAll that element; a call through it
  // would throw, and a page-supplied function would choose the target.
  page.login.querySelectorAll = decoy;
  page.login.getAttribute = () => 'text';
  assert.deepEqual(page.run(fillInPage, [ORIGIN, 'alice', 's3cret', false]), { filled: true });
  assert.equal(page.user.value, 'alice');
  assert.equal(decoy.value, '');
});

test('generate fills every visible password field and leaves the username', () => {
  const user = input('text');
  const fresh = input('password');
  const confirm = input('password');
  const run = inPage({ origin: ORIGIN, inputs: [user, fresh, confirm] });
  assert.deepEqual(run(fillInPage, [ORIGIN, null, 'Gen3rated!', true]), { filled: true });
  assert.equal(fresh.value, 'Gen3rated!');
  assert.equal(confirm.value, 'Gen3rated!');
  assert.equal(user.value, '');
});

test('a plain fill touches only the first password field', () => {
  const fresh = input('password');
  const confirm = input('PASSWORD');
  const run = inPage({ origin: ORIGIN, inputs: [fresh, confirm] });
  run(fillInPage, [ORIGIN, '', 'x', false]);
  assert.equal(fresh.value, 'x');
  assert.equal(confirm.value, '');
});

test('the username goes to the nearest usable text field before the password', () => {
  const far = input('text');
  const hidden = input('text', { visible: false });
  const checkbox = input('checkbox');
  const untyped = input(null);
  const secret = input('password');
  const after = input('text');
  const run = inPage({ origin: ORIGIN, inputs: [far, untyped, hidden, checkbox, secret, after] });
  run(fillInPage, [ORIGIN, 'bob', 'pw', false]);
  assert.equal(untyped.value, 'bob');
  assert.equal(far.value, '');
  assert.equal(after.value, '');
  assert.equal(hidden.value, '');
});

test('no username field is not an error', () => {
  const secret = input('password');
  const run = inPage({ origin: ORIGIN, inputs: [secret] });
  assert.deepEqual(run(fillInPage, [ORIGIN, 'bob', 'pw', false]), { filled: true });
});

test('the function is self-contained so executeScript can serialise it', () => {
  const source = fillInPage.toString();
  assert.doesNotMatch(source, /\bimport\b|\brequire\(/);
});
