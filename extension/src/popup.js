// Popup UI. Talks only to the background; never sees a stored password. Builds the DOM with
// createElement/textContent only (no HTML parsing of host data).

const MESSAGES = {
  DENIED: 'Denied in pm.',
  DENIED_LOCKED: 'pm is locked. Unlock it and try again.',
  DENIED_TIMEOUT: 'No answer in pm in time.',
  DENIED_BUSY: 'pm has too many requests waiting.',
  NOT_FOUND: 'That login is not registered for this site.',
  ORIGIN_MISMATCH: 'The page changed; nothing was filled.',
  NO_PASSWORD_FIELD: 'No password field on this page.',
  NOT_A_WEB_PAGE: 'pm only works on http and https pages.',
  HOST_UNAVAILABLE: 'pm is not installed or not running.',
  HOST_DISCONNECTED: 'pm stopped answering before it finished. Check pm, then try again.',
  INTERRUPTED: 'The request was interrupted before pm answered. Check pm, then try again.',
};

/** A short sentence for a refusal code. */
export function describe(code) {
  return MESSAGES[code] ?? `Refused (${code}).`;
}

/**
 * Renders the logins as buttons into list.
 *
 * @param {Document} doc
 * @param {Element} list
 * @param {{entry: string, title: string, username: string}[]} entries
 * @param {(entry: string) => void} onPick
 */
export function renderEntries(doc, list, entries, onPick) {
  list.replaceChildren();
  if (entries.length === 0) {
    const empty = doc.createElement('li');
    empty.textContent = 'No logins for this site.';
    list.append(empty);
    return;
  }
  for (const e of entries) {
    const item = doc.createElement('li');
    const button = doc.createElement('button');
    button.type = 'button';
    button.textContent = e.title;
    const user = doc.createElement('span');
    user.className = 'username';
    user.textContent = e.username;
    button.append(user);
    button.addEventListener('click', () => onPick(e.entry));
    item.append(button);
    list.append(item);
  }
}

/** Wires the popup to the background through runtime.sendMessage. */
export async function start(chrome, doc) {
  const status = doc.getElementById('status');
  // A rejected or empty answer means the background stopped (Chrome may stop an idle service
  // worker while pm waits for approval): say so instead of showing nothing.
  const send = async (msg) => {
    try {
      return (await chrome.runtime.sendMessage(msg)) ?? { ok: false, code: 'INTERRUPTED' };
    } catch {
      return { ok: false, code: 'INTERRUPTED' };
    }
  };
  const show = (reply, done) => {
    if (reply.ok) {
      status.textContent = done;
    } else if (reply.saved === true) {
      status.textContent = `Saved in pm as a new login, but not filled: ${describe(reply.code)}`;
    } else {
      status.textContent = describe(reply.code);
    }
  };

  const fill = async (entry) => {
    status.textContent = 'Waiting for approval in pm…';
    show(await send({ kind: 'fill', entry }), 'Filled.');
  };

  doc.getElementById('generate').addEventListener('submit', async (event) => {
    event.preventDefault();
    status.textContent = 'Waiting for approval in pm…';
    show(await send({
      kind: 'generate',
      username: doc.getElementById('gen-username').value,
      policy: {
        length: Number(doc.getElementById('gen-length').value),
        lower: doc.getElementById('gen-lower').checked,
        upper: doc.getElementById('gen-upper').checked,
        digits: doc.getElementById('gen-digits').checked,
        symbols: doc.getElementById('gen-symbols').checked,
      },
    }), 'New password saved in pm and filled.');
  });

  doc.getElementById('save').addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = doc.getElementById('save-password');
    const reply = await send({
      kind: 'save',
      username: doc.getElementById('save-username').value,
      password: password.value,
    });
    password.value = '';
    show(reply, 'Saved.');
  });

  const listed = await send({ kind: 'lookup' });
  if (!listed.ok) {
    show(listed, '');
    return;
  }
  doc.getElementById('origin').textContent = listed.origin;
  renderEntries(doc, doc.getElementById('entries'), listed.entries, fill);
}

if (globalThis.document?.getElementById('entries')) {
  start(globalThis.chrome, globalThis.document);
}
