// Growth Panel runtime for the GitHub Pages copy.
// Provides the small `dash` API the dashboard scripts use (data, calc, draw, params, setParams, colors, onData)
// and unlocks the encrypted files with the shared password: live.enc (Shopify numbers, refreshed by the VPS) and
// notes.enc (the dashboard page itself plus the hand-kept datasets, built on the owner's PC).
(function () {
  const FILES = ['live.enc', 'notes.enc'];
  const RELOAD_MS = 15 * 60 * 1000;
  const KEY_STORE = 'gp-key';
  const PERIOD_STORE = 'gp-period';

  const store = {
    get(area, k) { try { return window[area].getItem(k); } catch { return null; } },
    set(area, k, v) { try { window[area].setItem(k, v); } catch {} },
    del(k) { try { localStorage.removeItem(k); sessionStorage.removeItem(k); } catch {} },
  };
  const b64 = { to: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))), from: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)) };

  // ---- data registry ----
  let datasets = null;          // { id: { rows, meta } }
  let loadError = null;
  const calcs = new Map();      // id -> { inputs, fn }
  const draws = new Map();      // name -> fn(el)
  const dataHooks = [];
  let calcCache = new Map();
  let params = { period: store.get('localStorage', PERIOD_STORE) || '28d' };

  function data(id) {
    if (loadError) return { status: 'error', error: loadError };
    if (!datasets) return { status: 'loading' };
    if (calcs.has(id)) {
      if (calcCache.has(id)) return calcCache.get(id);
      const c = calcs.get(id);
      let out;
      const ins = c.inputs.map((i) => data(i));
      if (ins.some((d) => d.status !== 'ok')) out = { status: 'error', error: 'missing input' };
      else {
        try { out = { status: 'ok', data: c.fn(...ins.map((d) => d.data)) }; }
        catch (e) { console.error('calc', id, e); out = { status: 'error', error: String(e) }; }
      }
      calcCache.set(id, out);
      return out;
    }
    const ds = datasets[id];
    return ds ? { status: 'ok', data: ds.rows, meta: ds.meta } : { status: 'error', error: 'no dataset ' + id };
  }

  function drawAll() {
    calcCache = new Map();
    for (const [name, fn] of draws) {
      document.querySelectorAll(`[data-draw="${CSS.escape(name)}"]`).forEach((el) => {
        try { fn(el); } catch (e) { console.error('draw', name, e); }
      });
    }
    for (const fn of dataHooks) { try { fn(); } catch (e) { console.error(e); } }
  }

  window.dash = {
    data,
    calc(id, spec) { calcs.set(id, { inputs: spec.inputs || [], fn: spec.fn }); },
    draw(name, fn) { draws.set(name, fn); },
    params: () => ({ ...params }),
    setParams(p) {
      params = { ...params, ...p };
      if (p.period) store.set('localStorage', PERIOD_STORE, p.period);
      drawAll();
    },
    onData(fn) { dataHooks.push(fn); },
    colors: ['var(--gp-c1)', 'var(--gp-c2)', 'var(--gp-c3)', 'var(--gp-c4)', 'var(--gp-c5)'],
    lock() { store.del(KEY_STORE); location.reload(); },
  };

  // ---- decryption ----
  async function fetchSealed(name) {
    const res = await fetch(name + '?t=' + Date.now(), { cache: 'no-store' });
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
    return res.json();
  }
  async function deriveKey(password, salt, iter) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64.from(salt), iterations: iter }, base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function open(sealed, key) {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.from(sealed.iv) }, key, b64.from(sealed.ct));
    const text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    return JSON.parse(text);
  }
  let loadAll = async function (key) {
    const sealed = await Promise.all(FILES.map((f) => fetchSealed(f).catch((e) => ({ missing: String(e.message || e) }))));
    if (sealed.every((s) => s.missing)) throw new Error('No data files found yet.');
    const merged = {};
    let generated = '', page = null;
    for (const s of sealed) {
      if (s.missing) { console.warn(s.missing); continue; }
      const bundle = await open(s, key);   // throws on a wrong key
      Object.assign(merged, bundle.datasets);
      if (bundle.kind === 'live') generated = bundle.generated;
      if (bundle.page) page = bundle.page;
    }
    return { merged, generated, page };
  }

  // ---- lock screen ----
  const lock = () => document.getElementById('gp-lock');
  const panel = () => document.getElementById('gp-panel');
  let key = null, lastGenerated = null;

  // The dashboard markup and scripts arrive inside notes.enc; scripts are re-created so the browser runs them, in order.
  let mounted = false;
  function mount(html) {
    if (mounted || !html) return;
    const box = document.getElementById('gp-mount');
    box.innerHTML = html;
    box.querySelectorAll('script').forEach((old) => {
      const s = document.createElement('script');
      s.textContent = old.textContent;
      old.replaceWith(s);
    });
    mounted = true;
  }

  async function unlockWith(k) {
    const { merged, generated, page } = await loadAll(k);
    key = k; datasets = merged; lastGenerated = generated; loadError = null;
    if (!page) throw new Error('notes.enc is missing the page.');
    mount(page);
    lock().hidden = true;
    panel().hidden = false;
    drawAll();
  }

  async function tryRemembered() {
    const saved = store.get('localStorage', KEY_STORE) || store.get('sessionStorage', KEY_STORE);
    if (!saved) return false;
    try {
      const k = await crypto.subtle.importKey('raw', b64.from(saved), { name: 'AES-GCM' }, true, ['decrypt']);
      await unlockWith(k);
      return true;
    } catch (e) { console.warn('remembered key failed', e); store.del(KEY_STORE); return false; }
  }

  async function onSubmit(ev) {
    ev.preventDefault();
    const form = ev.currentTarget;
    const msg = form.querySelector('[data-msg]');
    const btn = form.querySelector('button');
    const pw = form.querySelector('input[type=password]').value;
    const remember = form.querySelector('input[type=checkbox]').checked;
    msg.textContent = 'Unlocking…'; btn.disabled = true;
    try {
      const first = await fetchSealed('live.enc').catch(() => fetchSealed('notes.enc'));
      const k = await deriveKey(pw, first.salt, first.iter);
      await unlockWith(k);
      const raw = b64.to(await crypto.subtle.exportKey('raw', k));
      store.set(remember ? 'localStorage' : 'sessionStorage', KEY_STORE, raw);
      msg.textContent = '';
    } catch (e) {
      console.warn(e);
      msg.textContent = e instanceof DOMException || /operation/i.test(String(e)) ? 'Wrong password.' : 'Could not load the data: ' + (e.message || e);
    } finally { btn.disabled = false; }
  }

  // Pick up the VPS's next refresh without a page reload.
  async function poll() {
    if (!key || document.hidden) return;
    try {
      const { merged, generated } = await loadAll(key);
      if (generated !== lastGenerated) { datasets = merged; lastGenerated = generated; drawAll(); }
    } catch (e) { console.warn('reload failed', e); }
  }

  let resizeTimer = null;
  window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => datasets && drawAll(), 200); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  setInterval(poll, RELOAD_MS);

  // Plain mode (the TSF Store tool on the home server): no password, data straight from window.GP_PLAIN.
  async function loadPlain() {
    const res = await fetch(window.GP_PLAIN + '?t=' + Date.now(), { cache: 'no-store' });
    if (!res.ok) throw new Error('growth data: HTTP ' + res.status);
    const b = await res.json();
    if (b.generated !== lastGenerated) { datasets = b.datasets; lastGenerated = b.generated; loadError = null; mount(b.page); drawAll(); }
  }
  if (window.GP_PLAIN) {
    key = 'plain';
    loadAll = async () => { await loadPlain(); return { merged: datasets, generated: lastGenerated }; };
  }

  document.addEventListener('DOMContentLoaded', async () => {
    if (window.GP_PLAIN) {
      const out = document.getElementById('gp-signout'); if (out) { out.textContent = '← TSF Store'; out.href = '/'; }
      panel().hidden = false;
      try { await loadPlain(); } catch (e) { loadError = String(e.message || e); document.getElementById('gp-mount').textContent = 'Could not load the numbers: ' + loadError; }
      return;
    }
    document.getElementById('gp-lock-form').addEventListener('submit', onSubmit);
    const out = document.getElementById('gp-signout');
    if (out) out.addEventListener('click', (e) => { e.preventDefault(); dash.lock(); });
    if (!(await tryRemembered())) { lock().hidden = false; lock().querySelector('input[type=password]').focus(); }
  });
})();
