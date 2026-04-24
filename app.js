/*
 * Dev TOTP Client
 * - Pure static, no backend, no external fetch.
 * - RFC 6238 TOTP using Web Crypto (HMAC-SHA1/256/512).
 * - Accounts stored in localStorage under STORAGE_KEY.
 */
(function () {
  'use strict';

  const STORAGE_KEY = 'dev_totp_accounts_v1';
  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  // 2π × r where r = 18 (ring SVG radius)
  const RING_CIRCUM = 113.097;

  // ---------- Base32 ----------

  function normalizeSecret(input) {
    return String(input || '')
      .replace(/\s+/g, '')
      .replace(/-/g, '')
      .replace(/=+$/g, '')
      .toUpperCase();
  }

  function base32Decode(input) {
    const s = normalizeSecret(input);
    if (!s) throw new Error('Secret が空です');
    if (!/^[A-Z2-7]+$/.test(s)) throw new Error('Base32 に含まれない文字があります');
    let bits = 0;
    let value = 0;
    const out = [];
    for (const ch of s) {
      const idx = BASE32_ALPHABET.indexOf(ch);
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.push((value >>> bits) & 0xff);
      }
    }
    if (out.length === 0) throw new Error('Base32 のデコード結果が空です');
    return new Uint8Array(out);
  }

  // ---------- HMAC / TOTP ----------

  const ALGO_MAP = { 'SHA-1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA-512': 'SHA-512' };

  async function hmac(algorithm, keyBytes, msgBytes) {
    const hash = ALGO_MAP[algorithm] || 'SHA-1';
    const key = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: { name: hash } }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
    return new Uint8Array(sig);
  }

  // Dynamic truncation per RFC 4226
  function dynamicTruncate(mac, digits) {
    const offset = mac[mac.length - 1] & 0x0f;
    const bin =
      ((mac[offset] & 0x7f) << 24) |
      ((mac[offset + 1] & 0xff) << 16) |
      ((mac[offset + 2] & 0xff) << 8) |
      (mac[offset + 3] & 0xff);
    return String(bin % Math.pow(10, digits)).padStart(digits, '0');
  }

  async function generateTOTP(secret, opts) {
    const { digits = 6, period = 30, algorithm = 'SHA-1', time = Date.now() } = opts || {};
    const keyBytes = base32Decode(secret);
    const counter = BigInt(Math.floor(time / 1000 / period));
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, counter, false);
    const mac = await hmac(algorithm, keyBytes, new Uint8Array(buf));
    return dynamicTruncate(mac, digits);
  }

  function counterFor(time, period) {
    return Math.floor(time / 1000 / period);
  }

  function formatCode(code) {
    const mid = Math.ceil(code.length / 2);
    return code.slice(0, mid) + ' ' + code.slice(mid);
  }

  // ---------- otpauth:// URI ----------

  function parseOtpauthUri(uri) {
    if (!uri || !/^otpauth:\/\//i.test(uri)) return null;
    let u;
    try { u = new URL(uri); } catch { return null; }
    if (u.hostname !== 'totp') return null;

    const label = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
    let issuer = '';
    let accountName = label;
    if (label.includes(':')) {
      const idx = label.indexOf(':');
      issuer = label.slice(0, idx).trim();
      accountName = label.slice(idx + 1).trim();
    }
    const params = u.searchParams;
    const secret = params.get('secret') || '';
    const qIssuer = params.get('issuer');
    if (qIssuer) issuer = qIssuer;

    const digits = parseInt(params.get('digits') || '6', 10);
    const period = parseInt(params.get('period') || '30', 10);
    const raw = (params.get('algorithm') || 'SHA1').toUpperCase();
    const algoRev = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

    return {
      secret,
      issuer,
      accountName,
      digits: Number.isFinite(digits) && digits > 0 ? digits : 6,
      period: Number.isFinite(period) && period > 0 ? period : 30,
      algorithm: algoRev[raw] || 'SHA-1',
    };
  }

  // ---------- Storage ----------

  function loadAccounts() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveAccounts(list) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  }

  function makeId() {
    const a = new Uint8Array(8);
    crypto.getRandomValues(a);
    return Array.from(a, b => b.toString(16).padStart(2, '0')).join('');
  }

  // ---------- State ----------

  let accounts = [];
  const cardRefs = new Map(); // id -> { el, refs, lastCode, lastCounter }

  // ---------- DOM ----------

  const $ = (s, r = document) => r.querySelector(s);
  let form, inpIssuer, inpAccount, inpSecret, btnDemo, btnClearAll;
  let listEl, emptyEl, errEl, toastEl, tpl;

  // ---------- Toast ----------

  let toastTimer = null;
  function toast(msg, opts) {
    const error = opts && opts.error;
    if (toastTimer) clearTimeout(toastTimer);
    toastEl.textContent = msg;
    toastEl.classList.toggle('is-err', !!error);
    toastEl.classList.add('is-show');
    toastTimer = setTimeout(() => toastEl.classList.remove('is-show'), 2000);
  }

  function setError(msg) {
    errEl.textContent = msg || '';
  }

  // ---------- Render ----------

  function renderAll() {
    listEl.innerHTML = '';
    cardRefs.clear();
    if (accounts.length === 0) {
      emptyEl.hidden = false;
      document.body.classList.remove('is-crit');
      return;
    }
    emptyEl.hidden = true;
    for (const acc of accounts) renderCard(acc);
  }

  function renderCard(account) {
    const node = tpl.content.firstElementChild.cloneNode(true);
    node.dataset.id = account.id;

    const refs = {
      issuer: node.querySelector('[data-role="issuer"]'),
      account: node.querySelector('[data-role="account"]'),
      code: node.querySelector('[data-role="code"]'),
      countdown: node.querySelector('[data-role="countdown"]'),
      bar: node.querySelector('[data-role="bar"]'),
      ring: node.querySelector('[data-role="ring"]'),
      secretRow: node.querySelector('[data-role="secret-row"]'),
      secretVal: node.querySelector('[data-role="secret-value"]'),
      btnCopy: node.querySelector('[data-act="copy"]'),
      btnToggle: node.querySelector('[data-act="toggle-secret"]'),
      btnDel: node.querySelector('[data-act="delete"]'),
    };

    refs.issuer.textContent = account.issuer || '(no issuer)';
    refs.account.textContent = account.accountName || '';
    refs.secretVal.textContent = account.secret;

    refs.btnCopy.addEventListener('click', () => copyCodeFor(account.id));
    refs.btnToggle.addEventListener('click', () => toggleSecretFor(account.id));
    refs.btnDel.addEventListener('click', () => deleteAccount(account.id));

    listEl.appendChild(node);
    cardRefs.set(account.id, { el: node, refs, lastCode: null, lastCounter: null });
  }

  // ---------- Tick (runs every second) ----------

  async function tick() {
    const now = Date.now();
    let anyCrit = false;

    for (const account of accounts) {
      const ref = cardRefs.get(account.id);
      if (!ref) continue;
      const { refs, el } = ref;

      const period = account.period || 30;
      const elapsed = (now / 1000) % period;
      const remaining = Math.max(0, period - elapsed);
      const secLeft = Math.ceil(remaining);
      const frac = remaining / period;

      refs.countdown.textContent = secLeft + 's';
      refs.bar.style.transform = 'scaleX(' + frac.toFixed(4) + ')';
      refs.ring.style.strokeDasharray = RING_CIRCUM.toFixed(3);
      refs.ring.style.strokeDashoffset = (RING_CIRCUM * (1 - frac)).toFixed(3);

      el.classList.toggle('is-warn', secLeft <= 10 && secLeft > 5);
      el.classList.toggle('is-crit', secLeft <= 5);
      if (secLeft <= 5) anyCrit = true;

      // Only recompute the code when the 30s window changes
      const counter = counterFor(now, period);
      if (ref.lastCounter !== counter) {
        try {
          const code = await generateTOTP(account.secret, {
            digits: account.digits || 6,
            period,
            algorithm: account.algorithm || 'SHA-1',
            time: now,
          });
          const formatted = formatCode(code);
          if (formatted !== ref.lastCode) {
            refs.code.textContent = formatted;
            if (ref.lastCode !== null) {
              // retrigger the glitch animation on code rollover
              el.classList.remove('is-glitch');
              void el.offsetWidth;
              el.classList.add('is-glitch');
            }
            ref.lastCode = formatted;
          }
          el.classList.remove('is-error');
        } catch {
          refs.code.textContent = 'ERROR';
          ref.lastCode = 'ERROR';
          el.classList.add('is-error');
        }
        ref.lastCounter = counter;
      }
    }

    document.body.classList.toggle('is-crit', anyCrit && accounts.length > 0);
  }

  // ---------- Per-card actions ----------

  async function copyCodeFor(id) {
    const ref = cardRefs.get(id);
    if (!ref) return;
    const raw = (ref.refs.code.textContent || '').replace(/\s+/g, '');
    if (!raw || /[•·]/.test(raw) || ref.el.classList.contains('is-error')) {
      toast('コピーできるコードがありません', { error: true });
      return;
    }
    try {
      await navigator.clipboard.writeText(raw);
      toast('CODE COPIED');
    } catch {
      // Fallback for permission-restricted contexts
      try {
        const ta = document.createElement('textarea');
        ta.value = raw;
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast('CODE COPIED');
      } catch {
        toast('コピーに失敗', { error: true });
      }
    }
  }

  function toggleSecretFor(id) {
    const ref = cardRefs.get(id);
    if (!ref) return;
    const nowHidden = !ref.refs.secretRow.hidden;
    ref.refs.secretRow.hidden = nowHidden;
    const label = ref.refs.btnToggle.querySelector('.btn__label');
    if (label) label.textContent = nowHidden ? 'Secret 表示' : 'Secret 非表示';
  }

  function deleteAccount(id) {
    if (!confirm('このアカウントを削除しますか?')) return;
    accounts = accounts.filter(a => a.id !== id);
    cardRefs.delete(id);
    saveAccounts(accounts);
    renderAll();
    toast('ACCOUNT DELETED');
  }

  // ---------- Add flow ----------

  async function addAccount({ issuer, accountName, secret }) {
    let iss = (issuer || '').trim();
    let acc = (accountName || '').trim();
    let sec = (secret || '').trim();
    let digits = 6, period = 30, algorithm = 'SHA-1';

    const parsed = parseOtpauthUri(sec);
    if (parsed) {
      iss = iss || parsed.issuer;
      acc = acc || parsed.accountName;
      sec = parsed.secret;
      digits = parsed.digits;
      period = parsed.period;
      algorithm = parsed.algorithm;
    }

    sec = normalizeSecret(sec);
    if (!sec) throw new Error('Secret Key を入力してください');

    // Will throw if malformed
    base32Decode(sec);

    // Probe once to confirm Web Crypto accepts the material
    try {
      await generateTOTP(sec, { digits, period, algorithm });
    } catch (e) {
      throw new Error('Secret の検証に失敗: ' + e.message);
    }

    const entry = {
      id: makeId(),
      issuer: iss,
      accountName: acc,
      secret: sec,
      digits,
      period,
      algorithm,
      createdAt: new Date().toISOString(),
    };
    accounts.push(entry);
    saveAccounts(accounts);
    renderAll();
    tick();
    toast('ACCOUNT ADDED');
  }

  function onSubmit(ev) {
    ev.preventDefault();
    setError('');
    addAccount({
      issuer: inpIssuer.value,
      accountName: inpAccount.value,
      secret: inpSecret.value,
    }).then(() => {
      inpIssuer.value = '';
      inpAccount.value = '';
      inpSecret.value = '';
    }).catch(err => {
      setError(err.message || String(err));
    });
  }

  function onDemo() {
    setError('');
    // [DEMO] prefix makes it unambiguous that these are not real credentials
    const demos = [
      { issuer: '[DEMO] RFC 6238', accountName: 'test-vector@example.com', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' },
      { issuer: '[DEMO] Service-A', accountName: 'alice@dev.local',         secret: 'JBSWY3DPEHPK3PXP' },
      { issuer: '[DEMO] Service-B', accountName: 'bob@dev.local',           secret: 'KRSXG5CTMVRXEZLU' },
    ];
    const pick = demos[Math.floor(Math.random() * demos.length)];
    const dup = accounts.find(a => a.issuer === pick.issuer && a.accountName === pick.accountName);
    if (dup) pick.accountName = pick.accountName + '+' + Math.floor(Math.random() * 900 + 100);
    addAccount(pick).catch(err => setError(err.message));
  }

  function onClearAll() {
    if (accounts.length === 0) {
      toast('何も登録されていません');
      return;
    }
    if (!confirm('すべてのアカウントを削除しますか? この操作は元に戻せません。')) return;
    accounts = [];
    cardRefs.clear();
    localStorage.removeItem(STORAGE_KEY);
    renderAll();
    toast('ALL DATA CLEARED');
  }

  // Ripple effect on primary buttons — positions the highlight at the click point
  function onRipple(e) {
    const btn = e.target.closest('.btn--primary');
    if (!btn) return;
    const r = btn.getBoundingClientRect();
    btn.style.setProperty('--rx', ((e.clientX - r.left) / r.width * 100) + '%');
    btn.style.setProperty('--ry', ((e.clientY - r.top) / r.height * 100) + '%');
    btn.classList.remove('is-ripple');
    void btn.offsetWidth;
    btn.classList.add('is-ripple');
    setTimeout(() => btn.classList.remove('is-ripple'), 600);
  }

  // ---------- Init ----------

  function init() {
    if (!window.crypto || !window.crypto.subtle) {
      document.body.innerHTML = '<p style="padding:20px;color:#ff3344">このブラウザは Web Crypto API をサポートしていません。</p>';
      return;
    }

    form = $('#add-form');
    inpIssuer = $('#input-issuer');
    inpAccount = $('#input-account');
    inpSecret = $('#input-secret');
    btnDemo = $('#btn-demo');
    btnClearAll = $('#btn-clear-all');
    listEl = $('#account-list');
    emptyEl = $('#empty-state');
    errEl = $('#form-error');
    toastEl = $('#toast');
    tpl = $('#tpl-card');

    accounts = loadAccounts();
    renderAll();
    tick();

    form.addEventListener('submit', onSubmit);
    btnDemo.addEventListener('click', onDemo);
    btnClearAll.addEventListener('click', onClearAll);
    document.addEventListener('click', onRipple);

    setInterval(tick, 1000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
