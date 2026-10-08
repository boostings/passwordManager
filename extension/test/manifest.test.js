// T-EXT-06 / SR-308: minimal permissions, strict CSP, no remote code, no inline script.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = join(ROOT, 'src');
const manifest = JSON.parse(readFileSync(join(SRC, 'manifest.json'), 'utf8'));
const files = readdirSync(SRC);
const read = (name) => readFileSync(join(SRC, name), 'utf8');

test('Manifest V3 with exactly the three justified permissions', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ['nativeMessaging', 'activeTab', 'scripting']);
});

test('no host access, content scripts or web-accessible resources', () => {
  for (const key of ['host_permissions', 'optional_permissions', 'optional_host_permissions', 'content_scripts',
    'web_accessible_resources', 'key', 'update_url', 'oauth2', 'sandbox', 'chrome_url_overrides']) {
    assert.ok(!(key in manifest), key);
  }
  assert.deepEqual(Object.keys(manifest).sort(), ['action', 'background', 'content_security_policy', 'description',
    'externally_connectable', 'manifest_version', 'minimum_chrome_version', 'name', 'permissions', 'version']);
});

test('no other extension and no web page may connect (externally_connectable allows nothing)', () => {
  // An empty "ids" list admits no extension; with no "matches" key no web page may connect either.
  assert.deepEqual(manifest.externally_connectable, { ids: [] });
});

test('the extension-page CSP allows only packaged scripts and styles', () => {
  assert.deepEqual(Object.keys(manifest.content_security_policy), ['extension_pages']);
  const csp = manifest.content_security_policy.extension_pages;
  const directives = Object.fromEntries(csp.split(';').map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v]));
  assert.deepEqual(directives['default-src'], ["'none'"]);
  assert.deepEqual(directives['script-src'], ["'self'"]);
  assert.deepEqual(directives['style-src'], ["'self'"]);
  assert.deepEqual(directives['object-src'], ["'none'"]);
  assert.doesNotMatch(csp, /unsafe|https?:|\*|data:|blob:/);
});

test('every file the manifest names exists and is packaged', () => {
  const named = [manifest.background.service_worker, manifest.action.default_popup];
  for (const name of named) {
    assert.ok(files.includes(name), name);
  }
  assert.equal(manifest.background.type, 'module');
});

test('no remote code, eval or HTML injection in any script', () => {
  const scripts = files.filter((f) => f.endsWith('.js'));
  assert.ok(scripts.length >= 4);
  for (const name of scripts) {
    const source = read(name);
    for (const banned of [/\beval\s*\(/, /new\s+Function\s*\(/, /\binnerHTML\b/, /\bouterHTML\b/, /insertAdjacentHTML/,
      /document\.write/, /https?:\/\//, /\bimport\s*\(/, /importScripts/, /setTimeout\s*\(\s*['"`]/, /\bfetch\s*\(/,
      /XMLHttpRequest/, /WebSocket/, /onMessageExternal/, /onConnectExternal/, /connectNative/, /localStorage/,
      /chrome\.storage/]) {
      assert.doesNotMatch(source, banned, `${name}: ${banned}`);
    }
    for (const [, target] of source.matchAll(/from\s+'([^']+)'/g)) {
      assert.match(target, /^\.\/[a-z]+\.js$/, `${name} imports only packaged modules`);
      assert.ok(files.includes(target.slice(2)), target);
    }
  }
});

test('the popup has no inline script, handlers or styles', () => {
  const html = read('popup.html');
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1);
  for (const [, attributes, body] of scripts) {
    assert.equal(body.trim(), '');
    assert.match(attributes, /\bsrc="popup\.js"/);
  }
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
  assert.doesNotMatch(html, /<style\b/i);
  assert.doesNotMatch(html, /javascript:/i);
  for (const [, href] of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
    assert.ok(files.includes(href), href);
  }
});

test('the native host manifest template allows exactly one extension origin', () => {
  const host = JSON.parse(readFileSync(join(ROOT, 'native-host', 'pm.browser.json.template'), 'utf8'));
  assert.deepEqual(Object.keys(host).sort(), ['allowed_origins', 'description', 'name', 'path', 'type']);
  assert.equal(host.name, 'pm.browser');
  assert.equal(host.type, 'stdio');
  assert.equal(host.path, '__HOST_PATH__');
  assert.deepEqual(host.allowed_origins, ['chrome-extension://__EXTENSION_ID__/']);
  assert.match(read('bridge.js'), /export const HOST = 'pm\.browser';/);
});
