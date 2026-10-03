// The function injected into the page to fill a login (ADR 0014 §7, SR-309).
//
// chrome.scripting.executeScript serialises this function's source and runs it in the page's
// isolated world, so it must be self-contained: no imports, no closures, only its arguments.
// It refuses unless it runs in the top-level frame AND the page's origin still equals the origin
// the native host approved. A tab that navigated, or a frame of another origin, gets nothing.
//
// DOM methods are called through the prototypes, never as properties of page nodes: a form
// control named "querySelectorAll" (or "getAttribute") shadows that property on its form.
// Only fields the user can see get a value: rendered, visible, not transparent (checked up the
// ancestor chain by checkVisibility), with a non-zero box, enabled and writable.

/**
 * @param {string} approvedOrigin origin echoed by the host for this release
 * @param {string|null} username value for the username field, or null to leave it
 * @param {string} password value for the password field(s)
 * @param {boolean} everyPasswordField fill every visible password field (new + confirm), not just the first
 * @returns {{filled: boolean, reason?: string}}
 */
export function fillInPage(approvedOrigin, username, password, everyPasswordField) {
  if (window.top !== window || location.origin !== approvedOrigin) {
    return { filled: false, reason: 'ORIGIN_MISMATCH' };
  }
  const query = (root, selector) =>
    Array.from((root === document ? Document : Element).prototype.querySelectorAll.call(root, selector));
  const typeOf = (el) => (Element.prototype.getAttribute.call(el, 'type') ?? '').toLowerCase();
  const formOf = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'form').get;
  const visible = { opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true };
  const usable = (el) => {
    if (el.disabled || el.readOnly || !Element.prototype.checkVisibility.call(el, visible)) {
      return false;
    }
    const box = Element.prototype.getBoundingClientRect.call(el);
    return box.width > 0 && box.height > 0;
  };
  const set = (el, value) => {
    el.focus();
    el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const passwords = query(document, 'input').filter((el) => typeOf(el) === 'password' && usable(el));
  if (passwords.length === 0) {
    return { filled: false, reason: 'NO_PASSWORD_FIELD' };
  }
  const first = passwords[0];
  for (const field of everyPasswordField ? passwords : [first]) {
    set(field, password);
  }
  if (username !== null && username !== '') {
    const inputs = query(formOf.call(first) ?? document, 'input');
    const textual = new Set(['text', 'email', 'tel', '']);
    for (let i = inputs.indexOf(first) - 1; i >= 0; i--) {
      const candidate = inputs[i];
      if (textual.has(typeOf(candidate)) && usable(candidate)) {
        set(candidate, username);
        break;
      }
    }
  }
  return { filled: true };
}
