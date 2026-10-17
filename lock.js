/* Album lock: opens the encrypted part of data.json with the 4-digit album code.
   Scheme (matches album_lock.py): PBKDF2-HMAC-SHA256 (iter from the blob, 200000) -> AES-256-GCM,
   ct = ciphertext||16-byte tag (WebCrypto layout). Plain ES2017, no modules; window.AlbumLock in the
   browser, globalThis.AlbumLock (and module.exports) under Node. See LOCK.md. */
(function (root) {
  'use strict';
  var subtle = root.crypto && root.crypto.subtle;
  var STORE_KEY = 'album_lock_key';

  function b64(bytes) {
    var s = '', CH = 0x8000;
    for (var i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    return btoa(s);
  }
  function unb64(str) {
    var s = atob(str), out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function need() { if (!subtle) throw new Error('no-webcrypto'); }

  function deriveKey(pin, saltB64, iter) {
    need();
    return subtle.importKey('raw', new TextEncoder().encode(String(pin)), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: iter || 200000 },
          base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      });
  }
  function checkFormat(locked) {
    if (!locked || locked.v !== 1 || locked.kdf !== 'PBKDF2-SHA256' || !locked.iv || !locked.ct) throw new Error('bad-format');
  }
  function openWith(key, locked) {
    return subtle.decrypt({ name: 'AES-GCM', iv: unb64(locked.iv) }, key, unb64(locked.ct))
      .then(function (pt) { return JSON.parse(new TextDecoder().decode(pt)); },
            function () { throw new Error('wrong-code'); });
  }
  function exportRaw(key) {
    return subtle.exportKey('raw', key).then(function (raw) { return b64(new Uint8Array(raw)); });
  }
  /* -> Promise<obj>; rejects Error('wrong-code') on a failed tag */
  function unlockFull(locked, pin) {
    return Promise.resolve().then(function () { checkFormat(locked); return deriveKey(pin, locked.salt, locked.iter); })
      .then(function (key) {
        return openWith(key, locked).then(function (obj) { return exportRaw(key).then(function (raw) { return { obj: obj, raw: raw }; }); });
      });
  }
  function unlock(locked, pin) { return unlockFull(locked, pin).then(function (r) { return r.obj; }); }
  function unlockWithRaw(locked, rawKeyB64) {
    return Promise.resolve().then(function () {
      checkFormat(locked); need();
      return subtle.importKey('raw', unb64(rawKeyB64), { name: 'AES-GCM' }, false, ['decrypt']);
    }).then(function (key) { return openWith(key, locked); },
            function (e) { throw e.message === 'bad-format' ? e : new Error('wrong-code'); });
  }
  /* test helper: encrypt like album_lock.py (used by `python3 album_lock.py --test`) */
  function lock(obj, pin, saltB64, iter) {
    var iv = root.crypto.getRandomValues(new Uint8Array(12));
    return deriveKey(pin, saltB64, iter).then(function (key) {
      return subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
    }).then(function (ct) {
      return { v: 1, kdf: 'PBKDF2-SHA256', iter: iter || 200000, salt: saltB64, iv: b64(iv), ct: b64(new Uint8Array(ct)) };
    });
  }

  function storage() { try { return root.localStorage || null; } catch (e) { return null; } }
  function remember(raw) { try { var s = storage(); if (s) s.setItem(STORE_KEY, raw); } catch (e) {} }
  function cached() { try { var s = storage(); return (s && s.getItem(STORE_KEY)) || null; } catch (e) { return null; } }
  function forget() { try { var s = storage(); if (s) s.removeItem(STORE_KEY); } catch (e) {} }

  /* ---------- the gate ---------- */
  var STR = {
    en: { line: 'Enter the album code', label: 'Album code, four digits', keep: 'Keep me signed in on this phone',
          open: 'Open the album', busy: 'Opening the album…', wrong: 'That code is not right. Please try again.',
          short: 'The code has four digits.', fail: 'This phone could not open the album. Please try again.' },
    hi: { line: 'एल्बम कोड डालें', label: 'एल्बम कोड, चार अंक',
          keep: 'इस फ़ोन पर मुझे साइन इन रखें',
          open: 'एल्बम खोलें', busy: 'एल्बम खुल रहा है…',
          wrong: 'यह कोड सही नहीं है। फिर से कोशिश करें।',
          short: 'कोड में चार अंक हैं।',
          fail: 'यह फ़ोन एल्बम नहीं खोल पाया। फिर से कोशिश करें।' }
  };
  /* Tone only: the field is a well of the deeper tray colour, state is ink and weight. No borders, pills or lines. */
  var CSS =
    '.alock{max-width:22rem;margin:0 auto;padding:2.5rem 16px 2rem;text-align:center;color:var(--cream-text-on-baize,inherit);font-family:var(--body,inherit)}' +
    '.alock-line{font-family:var(--display,inherit);font-weight:600;font-size:1.625rem;line-height:1.2;color:var(--cream,inherit);margin:0 0 1.25rem;font-optical-sizing:auto}' +
    '.alock-pin{display:block;width:100%;max-width:15rem;margin:0 auto;min-height:4.5rem;padding:.25rem 0 .25rem .55em;border:0;border-radius:14px;' +
      'background:rgba(0,0,0,.14);transition:background-color .15s;color:var(--cream,inherit);font-family:var(--display,inherit);font-weight:600;font-size:2.75rem;' +
      'letter-spacing:.55em;text-align:center;font-variant-numeric:tabular-nums lining-nums;caret-color:var(--brass,currentColor);-webkit-appearance:none;appearance:none}' +
    '.alock-pin::placeholder{color:var(--felt-quiet,currentColor);opacity:.55}' +
    '.alock-pin:focus,.alock-pin:focus-visible{outline:none;background:var(--baize-deep,rgba(0,0,0,.3))}' +  /* focus = the well deepens (tone), the brass caret blinks inside */
    '.alock-pin[readonly]{color:var(--felt-quiet,inherit)}' +
    '@media (prefers-reduced-motion:reduce){.alock-pin{transition:none}}' +
    '.alock-msg{min-height:3.2em;margin:.9rem 0 .4rem;font-size:1.125rem;line-height:1.4;color:var(--felt-quiet,inherit)}' +
    '.alock-msg[data-kind="wrong"]{color:var(--cream,inherit);font-weight:700}' +
    '.alock-keep{display:inline-flex;align-items:center;gap:.75rem;min-height:var(--tap,48px);padding:0 .5rem;font-size:1.125rem;color:var(--cream-text-on-baize,inherit);cursor:pointer;text-align:left}' +
    '.alock-keep input{width:28px;height:28px;margin:0;flex-shrink:0;accent-color:var(--brass,auto)}' +
    '.alock-go{display:block;margin:1rem auto 0;min-height:var(--tap,48px);min-width:12rem;padding:0 1.25rem;border:0;border-radius:12px;background:transparent;' +
      'font:inherit;font-size:1.1875rem;font-weight:700;color:var(--brass-soft,inherit);cursor:pointer;-webkit-tap-highlight-color:transparent}' +
    '.alock-go:active,.alock-go:focus-visible{outline:none;background:var(--baize-deep,rgba(0,0,0,.2))}' +
    '.alock-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}';

  function injectStyle(doc) {
    if (doc.getElementById('album-lock-style')) return;
    var st = doc.createElement('style'); st.id = 'album-lock-style'; st.textContent = CSS;
    (doc.head || doc.documentElement).appendChild(st);
  }

  /* Renders the code entry into container; on success empties it, then calls onUnlock(obj, rawKeyB64).
     Returns { destroy() }. Call again (e.g. on a language switch) to re-render. */
  function mountGate(container, opts) {
    opts = opts || {};
    var doc = container.ownerDocument, t = STR[opts.lang === 'hi' ? 'hi' : 'en'], uid = 'alock' + Math.random().toString(36).slice(2, 8);
    injectStyle(doc);
    container.innerHTML =
      '<form class="alock" novalidate lang="' + (opts.lang === 'hi' ? 'hi' : 'en') + '">' +
        '<p class="alock-line" id="' + uid + '-l">' + t.line + '</p>' +
        '<input class="alock-pin" id="' + uid + '-p" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="one-time-code"' +
          ' autocorrect="off" autocapitalize="off" spellcheck="false" placeholder="••••" aria-label="' + t.label + '" aria-describedby="' + uid + '-m">' +
        '<p class="alock-msg" id="' + uid + '-m" role="status" aria-live="polite"></p>' +
        '<label class="alock-keep"><input type="checkbox" checked><span>' + t.keep + '</span></label>' +
        '<button class="alock-go" type="submit">' + t.open + '</button>' +
      '</form>';
    var form = container.querySelector('form'), pin = form.querySelector('.alock-pin'),
        msg = form.querySelector('.alock-msg'), keep = form.querySelector('.alock-keep input'), busy = false, dead = false;

    function say(text, kind) { msg.textContent = text; if (kind) msg.setAttribute('data-kind', kind); else msg.removeAttribute('data-kind'); }
    function submit() {
      if (busy || dead) return;
      var code = pin.value.replace(/\D/g, '');
      if (code.length !== 4) { say(t.short, 'wrong'); pin.focus(); return; }
      busy = true; pin.readOnly = true; pin.setAttribute('aria-busy', 'true'); say(t.busy);
      unlockFull(opts.locked, code).then(function (r) {
        if (dead) return;
        if (keep.checked) remember(r.raw); else forget();
        dead = true; container.innerHTML = '';
        if (opts.onUnlock) opts.onUnlock(r.obj, r.raw);
      }, function (e) {
        if (dead) return;
        busy = false; pin.readOnly = false; pin.removeAttribute('aria-busy');
        pin.value = ''; say(e && e.message === 'wrong-code' ? t.wrong : t.fail, 'wrong'); pin.focus();
      });
    }
    pin.addEventListener('input', function () {
      var d = pin.value.replace(/\D/g, '').slice(0, 4);
      if (d !== pin.value) pin.value = d;
      if (msg.getAttribute('data-kind') === 'wrong' && d.length) say('');
      if (d.length === 4) submit();
    });
    form.addEventListener('submit', function (ev) { ev.preventDefault(); submit(); });
    try { pin.focus({ preventScroll: true }); } catch (e) { pin.focus(); }
    return { destroy: function () { dead = true; container.innerHTML = ''; } };
  }

  var api = { deriveKey: deriveKey, unlock: unlock, unlockWithRaw: unlockWithRaw, remember: remember, cached: cached,
              forget: forget, mountGate: mountGate, strings: STR, _lock: lock, _b64: b64 };
  root.AlbumLock = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
