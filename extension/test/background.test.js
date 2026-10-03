// The service worker entry point installs exactly one message listener on the real chrome global.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { approvingHost, fakeChrome } from './fakes.js';

test('background.js wires createBackground to chrome.runtime.onMessage', async () => {
  const chrome = fakeChrome({ host: approvingHost(), runInPage: () => ({ filled: true }) });
  globalThis.chrome = chrome;
  try {
    await import('../src/background.js');
  } finally {
    delete globalThis.chrome;
  }
  assert.equal(chrome.listeners.length, 1);
});
