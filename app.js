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
  // RFC 6238 test vector key: ASCII "12345678901234567890" -> Base32
  const DEMO_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

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
  function dynamicTruncate(hmacBytes, digits) {
    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const bin =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);
    const mod = Math.pow(10, digits);
    return String(bin % mod).padStart(digits, '0');
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

  // ---------- otpauth:// URI ----------

  function parseOtpauthUri(uri) {
    if (!uri || !uri.startsWith('otpauth://')) return null;
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
    const algorithm = algoRev[raw] || 'SHA-1';

    return {
      secret,
      issuer,
      accountName,
      digits: Number.isFinite(digits) && digits > 0 ? digits : 6,
      period: Number.isFinite(period) && period > 0 ? period : 30,
      algorithm,
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

  function saveAccounts(accounts) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts));
  }

  function makeId() {
    // Random id, not used cryptographically
    const a = new Uint8Array(8);
    crypto.getRandomValues(a);
    return Array.from(a, b => b.toString(16).padStart(2, '0')).join('');
  }

  // ---------- UI ----------

  let accounts = [];
  const codeCache = new Map(); // id -> { counter, code }

  const $ = (sel) => document.querySelector(sel);
  const listEl = () => $('#account-list');
  const emptyEl = () => $('#empty-state');
  const errorEl = () => $('#form-error');
  const toastEl = () => $('#toast');

  function showToast(msg, kind) {
    const el = toastEl();
    el.textContent = msg;
    el.classList.remove('hidden', 'success', 'error');
    if (kind) el.classList.add(kind);
    el.classList.add('show');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.classList.add('hidden'), 220);
    }, 1600);
  }

  function setError(msg) {
    errorEl().textContent = msg || '';
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatCode(code) {
    if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3);
    if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4);
    return code;
  }

  function renderAll() {
    const list = listEl();
    list.innerHTML = '';
    if (accounts.length === 0) {
      emptyEl().classList.remove('hidden');
      return;
    }
    emptyEl().classList.add('hidden');

    for (const acc of accounts) {
      const card = document.createElement('div');
      card.className = 'account';
      card.dataset.id = acc.id;
      card.innerHTML = `
        <div class="account-head">
          <div class="account-title">
            <span class="account-issuer">${escapeHtml(acc.issuer || '(no issuer)')}</span>
            <span class="account-name">${escapeHtml(acc.accountName || '')}</span>
          </div>
          <div class="account-actions">
            <button type="button" class="btn btn-sm" data-act="toggle-secret">Secret 表示</button>
            <button type="button" class="btn btn-sm btn-danger" data-act="delete">削除</button>
          </div>
        </div>
        <div class="code-row">
          <div class="code" data-role="code" title="クリックでコピー">------</div>
          <button type="button" class="btn btn-sm" data-act="copy">コピー</button>
          <div class="countdown" data-role="countdown">--</div>
        </div>
        <div class="progress"><div class="progress-bar" data-role="bar"></div></div>
        <div class="secret-row hidden" data-role="secret-row">
          <span>Secret:</span>
          <span class="secret-value" data-role="secret-value">${escapeHtml(acc.secret)}</span>
        </div>
      `;
      list.appendChild(card);
    }

    // Wire up per-card actions via delegation on the list
  }

  async function tick() {
    const now = Date.now();
    const cards = listEl().querySelectorAll('.account');
    for (const card of cards) {
      const id = card.dataset.id;
      const acc = accounts.find(a => a.id === id);
      if (!acc) continue;

      const period = acc.period || 30;
      const elapsed = (now / 1000) % period;
      const remaining = Math.max(0, period - elapsed);
      const secLeft = Math.ceil(remaining);
      const pct = (remaining / period) * 100;

      const countdownEl = card.querySelector('[data-role="countdown"]');
      const barEl = card.querySelector('[data-role="bar"]');
      const codeEl = card.querySelector('[data-role="code"]');

      countdownEl.textContent = String(secLeft) + 's';
      countdownEl.classList.toggle('warn', secLeft <= 10 && secLeft > 5);
      countdownEl.classList.toggle('crit', secLeft <= 5);
      barEl.style.width = pct + '%';
      barEl.classList.toggle('warn', secLeft <= 10 && secLeft > 5);
      barEl.classList.toggle('crit', secLeft <= 5);

      const counter = counterFor(now, period);
      const cached = codeCache.get(id);
      if (cached && cached.counter === counter && cached.code) {
        codeEl.textContent = formatCode(cached.code);
        codeEl.classList.remove('invalid');
        continue;
      }
      try {
        const code = await generateTOTP(acc.secret, {
          digits: acc.digits || 6,
          period: acc.period || 30,
          algorithm: acc.algorithm || 'SHA-1',
          time: now,
        });
        codeCache.set(id, { counter, code });
        codeEl.textContent = formatCode(code);
        codeEl.classList.remove('invalid');
      } catch (e) {
        codeEl.textContent = 'Invalid: ' + (e.message || 'error');
        codeEl.classList.add('invalid');
      }
    }
  }

  // ---------- Event handlers ----------

  function onAddSubmit(ev) {
    ev.preventDefault();
    setError('');

    const issuerInput = $('#input-issuer').value.trim();
    const accountInput = $('#input-account').value.trim();
    const secretInput = $('#input-secret').value.trim();

    let acc;
    const parsed = parseOtpauthUri(secretInput);
    if (parsed) {
      acc = {
        id: makeId(),
        issuer: issuerInput || parsed.issuer || '',
        accountName: accountInput || parsed.accountName || '',
        secret: normalizeSecret(parsed.secret),
        digits: parsed.digits,
        period: parsed.period,
        algorithm: parsed.algorithm,
        createdAt: new Date().toISOString(),
      };
    } else {
      acc = {
        id: makeId(),
        issuer: issuerInput,
        accountName: accountInput,
        secret: normalizeSecret(secretInput),
        digits: 6,
        period: 30,
        algorithm: 'SHA-1',
        createdAt: new Date().toISOString(),
      };
    }

    if (!acc.secret) {
      setError('Secret Key を入力してください');
      return;
    }
    try {
      base32Decode(acc.secret);
    } catch (e) {
      setError('Secret Key が不正です: ' + e.message);
      return;
    }

    accounts.push(acc);
    saveAccounts(accounts);
    renderAll();
    tick();

    $('#add-form').reset();
    showToast('アカウントを追加しました', 'success');
  }

  function onListClick(ev) {
    const btn = ev.target.closest('button');
    if (!btn) {
      // clicking the code copies it
      const codeEl = ev.target.closest('[data-role="code"]');
      if (codeEl) {
        const card = codeEl.closest('.account');
        copyCode(card);
      }
      return;
    }
    const card = btn.closest('.account');
    if (!card) return;
    const id = card.dataset.id;
    const act = btn.dataset.act;

    if (act === 'delete') {
      if (!confirm('このアカウントを削除しますか?')) return;
      accounts = accounts.filter(a => a.id !== id);
      codeCache.delete(id);
      saveAccounts(accounts);
      renderAll();
      showToast('削除しました', 'success');
    } else if (act === 'toggle-secret') {
      const row = card.querySelector('[data-role="secret-row"]');
      const hidden = row.classList.toggle('hidden');
      btn.textContent = hidden ? 'Secret 表示' : 'Secret 非表示';
    } else if (act === 'copy') {
      copyCode(card);
    }
  }

  async function copyCode(card) {
    const codeEl = card.querySelector('[data-role="code"]');
    const raw = (codeEl.textContent || '').replace(/\s+/g, '');
    if (!raw || codeEl.classList.contains('invalid')) {
      showToast('コピーできるコードがありません', 'error');
      return;
    }
    try {
      await navigator.clipboard.writeText(raw);
      showToast('コピーしました', 'success');
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
        showToast('コピーしました', 'success');
      } catch {
        showToast('コピーに失敗しました', 'error');
      }
    }
  }

  function onClearAll() {
    if (accounts.length === 0) {
      showToast('削除対象がありません');
      return;
    }
    if (!confirm('localStorage 内の全アカウントを削除します。よろしいですか?')) return;
    accounts = [];
    codeCache.clear();
    localStorage.removeItem(STORAGE_KEY);
    renderAll();
    showToast('全データを削除しました', 'success');
  }

  function onDemo() {
    const acc = {
      id: makeId(),
      issuer: '[DEMO] RFC6238 Test Vector',
      accountName: 'demo@example.com (本番では絶対に使用しない)',
      secret: DEMO_SECRET,
      digits: 6,
      period: 30,
      algorithm: 'SHA-1',
      createdAt: new Date().toISOString(),
    };
    accounts.push(acc);
    saveAccounts(accounts);
    renderAll();
    tick();
    showToast('デモ用サンプルを追加しました', 'success');
  }

  // ---------- Init ----------

  function init() {
    if (!window.crypto || !window.crypto.subtle) {
      document.body.innerHTML = '<p style="padding:20px;color:#f87171">このブラウザは Web Crypto API をサポートしていません。</p>';
      return;
    }

    accounts = loadAccounts();
    renderAll();
    tick();

    $('#add-form').addEventListener('submit', onAddSubmit);
    $('#btn-demo').addEventListener('click', onDemo);
    $('#btn-clear-all').addEventListener('click', onClearAll);
    listEl().addEventListener('click', onListClick);

    // Update UI every second; TOTP value recomputed when counter changes.
    setInterval(tick, 1000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
