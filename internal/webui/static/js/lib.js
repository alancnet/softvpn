// Small helpers shared by the pages: DOM building (never innerHTML with
// data), the API client, toasts, dialogs, formatting and a line diff.

// h('div', {class: 'x', onclick: fn}, child, ...) builds an element.
// Children may be strings, nodes, arrays, or null/false (skipped).
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'readOnly' || k === 'required') el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

const SVGNS = 'http://www.w3.org/2000/svg';
const paths = {
  dashboard: 'M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z',
  clients: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  users: 'M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1M19 8v6M22 11h-6',
  key: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
  config: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  logs: 'M4 6h16M4 12h16M4 18h10',
  shield: 'M12 3l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V6l8-3zM9 12l2 2 4-4',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42',
  moon: 'M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z',
  auto: 'M12 3a9 9 0 1 0 0 18V3z M12 3a9 9 0 0 1 0 18',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  plus: 'M12 5v14M5 12h14',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
  trash: 'M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6',
  ban: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM4.93 4.93l14.14 14.14',
  edit: 'M12 20h9M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z',
  sliders: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
  power: 'M18.36 6.64a9 9 0 1 1-12.73 0M12 2v10',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
  alert: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01',
  info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01',
  check: 'M20 6L9 17l-5-5',
  checkCircle: 'M22 11.08V12a10 10 0 1 1-5.93-9.14M22 4L12 14.01l-3-3',
  x: 'M18 6L6 18M6 6l12 12',
  lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35',
  pause: 'M6 4h4v16H6zM14 4h4v16h-4z',
  play: 'M5 3l14 9-14 9V3z',
  server: 'M2 3h20v8H2zM2 13h20v8H2zM6 7h.01M6 17h.01',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  globe: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z',
  plug: 'M12 22v-5M9 8V2M15 8V2M18 8v5a6 6 0 0 1-12 0V8z',
  file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6',
  copy: 'M9 9h13v13H9zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
  wand: 'M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8L19 13M15 9h.01M17.8 6.2L19 5M3 21l9-9M12.2 6.2L11 5',
};

export function icon(name, cls) {
  const s = document.createElementNS(SVGNS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
  s.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(SVGNS, 'path');
  p.setAttribute('d', paths[name] || paths.info);
  s.append(p);
  return s;
}

// ---- API ----

let csrf = '';
export function setCSRF(t) { csrf = t || ''; }

export class APIError extends Error {
  constructor(status, body) {
    super((body && body.error) || `request failed (HTTP ${status})`);
    this.status = status;
    this.body = body || {};
  }
}

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

export async function api(method, path, body, opts = {}) {
  const headers = { 'Accept': 'application/json' };
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  if (opts.login) headers['X-Requested-With'] = 'softvpn';
  let payload;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch('/api' + path, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  } catch (e) {
    throw new APIError(0, { error: 'Cannot reach the server. Is softvpn running?' });
  }
  if (opts.raw && res.ok) return res;
  let data = null;
  const type = res.headers.get('Content-Type') || '';
  if (type.includes('json')) data = await res.json().catch(() => null);
  if (res.status === 401 && !opts.login) {
    onUnauthorized();
    throw new APIError(401, data);
  }
  if (!res.ok) throw new APIError(res.status, data);
  return data;
}

// download fetches a file from the API and saves it under its name.
export async function download(path, fallbackName) {
  const res = await api('GET', path, undefined, { raw: true });
  const blob = await res.blob();
  const cd = res.headers.get('Content-Disposition') || '';
  const m = /filename="([^"]+)"/.exec(cd);
  const a = h('a', { href: URL.createObjectURL(blob), download: m ? m[1] : fallbackName });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

// ---- toasts ----

export function toast(kind, title, msg, ms) {
  const root = document.getElementById('toasts');
  const close = h('button', { type: 'button', 'aria-label': 'Dismiss' }, icon('x'));
  const el = h('div', { class: 'toast ' + kind },
    icon(kind === 'ok' ? 'checkCircle' : kind === 'error' ? 'alert' : 'info'),
    h('div', null, h('strong', null, title), msg ? h('span', null, msg) : null),
    close);
  const remove = () => el.remove();
  close.addEventListener('click', remove);
  root.append(el);
  setTimeout(remove, ms || (kind === 'error' ? 9000 : 4500));
}

// ---- dialogs ----

// openDialog shows a modal <dialog>. build(close) returns {title, body,
// actions, icon, tone, wide}; close(value) resolves the returned promise.
export function openDialog(build) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { 'aria-labelledby': 'dlg-title' });
    let done = false;
    const close = (v) => {
      if (done) return;
      done = true;
      dlg.close();
      dlg.remove();
      resolve(v);
    };
    const spec = build(close);
    if (spec.wide) dlg.classList.add('wide');
    const head = h('div', { class: 'dlg-head' },
      spec.icon ? h('div', { class: 'dlg-icon ' + (spec.tone || '') }, icon(spec.icon)) : null,
      h('h2', { id: 'dlg-title' }, spec.title));
    const form = h('form', { class: 'dlg', method: 'dialog' }, head,
      h('div', { class: 'dlg-body' }, spec.body),
      h('div', { class: 'dlg-foot' }, spec.actions));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (spec.onSubmit) spec.onSubmit(e);
    });
    dlg.append(form);
    dlg.addEventListener('cancel', (e) => {
      if (spec.busy && spec.busy()) { e.preventDefault(); return; }
      close(undefined);
    });
    document.body.append(dlg);
    dlg.showModal();
    const focus = form.querySelector('[autofocus]') || form.querySelector('.dlg-foot .btn.primary, .dlg-foot .btn.danger') || form.querySelector('input, select, textarea, button');
    if (focus) focus.focus();
  });
}

// confirmDialog asks a yes/no question; resolves true on confirm.
export function confirmDialog({ title, message, confirm = 'Confirm', tone = 'danger', iconName = 'alert', details }) {
  return openDialog((close) => ({
    title, icon: iconName, tone,
    body: [typeof message === 'string' ? h('p', null, message) : message, details || null],
    actions: [
      h('button', { type: 'button', class: 'btn', onclick: () => close(false) }, 'Cancel'),
      h('button', { type: 'button', class: 'btn ' + (tone === 'danger' ? 'danger' : 'primary'), onclick: () => close(true) }, confirm),
    ],
  }));
}

// busy marks a button as working until the promise settles.
export async function busy(btn, fn) {
  const old = Array.from(btn.childNodes);
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.prepend(h('span', { class: 'spinner', 'aria-hidden': 'true' }));
  try {
    return await fn();
  } finally {
    btn.replaceChildren(...old);
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
  }
}

// ---- form helpers ----

let uid = 0;
export function field(label, input, hint, opts = {}) {
  const id = input.id || ('f' + (++uid));
  input.id = id;
  if (hint) input.setAttribute('aria-describedby', id + '-hint');
  return h('div', { class: 'field' + (opts.wide ? ' wide' : '') },
    h('label', { for: id }, label), input,
    hint ? h('div', { class: 'hint', id: id + '-hint' }, hint) : null);
}

export function checkbox(label, checked, hint, onchange) {
  const input = h('input', { type: 'checkbox', checked, onchange });
  return { el: h('label', { class: 'check' }, input, h('span', null, label, hint ? h('small', null, hint) : null)), input };
}

export function select(options, value, attrs) {
  const s = h('select', attrs || {});
  for (const o of options) {
    const [v, text] = Array.isArray(o) ? o : [o, o];
    s.append(h('option', { value: v, selected: v === value }, text));
  }
  if (value != null && ![...s.options].some((o) => o.value === value)) {
    s.append(h('option', { value, selected: true }, value));
  }
  return s;
}

export function banner(kind, title, text, action) {
  return h('div', { class: 'banner ' + kind, role: kind === 'danger' ? 'alert' : null },
    icon(kind === 'info' ? 'info' : 'alert'),
    h('div', null, h('strong', null, title), text ? h('p', null, text) : null),
    action || null);
}

export function empty(iconName, title, text, action) {
  return h('div', { class: 'empty' }, icon(iconName), h('strong', null, title), text ? h('p', null, text) : null, action || null);
}

export function loading(text = 'Loading…') {
  return h('div', { class: 'loading' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), text);
}

export function randomPassword(n = 16) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const b = new Uint32Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => alphabet[x % alphabet.length]).join('');
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('ok', 'Copied to the clipboard');
  } catch {
    toast('warn', 'Copy failed', 'Select the text and copy it yourself.');
  }
}

// ---- formatting ----

export function bytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1000)));
  const v = n / 1000 ** i;
  return (v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u[i];
}

export function duration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  if (d) return `${d}d ${hh}h`;
  if (hh) return `${hh}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

export function ago(iso, now = Date.now()) {
  if (!iso) return '—';
  return duration(now - new Date(iso).getTime()) + ' ago';
}

export function dateStr(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function dateTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

// ---- diff ----

// diffLines returns [{op: ' '|'+'|'-', line}] from an LCS of the two texts.
export function diffLines(a, b) {
  const x = a.replace(/\n$/, '').split('\n'), y = b.replace(/\n$/, '').split('\n');
  let pre = 0;
  while (pre < x.length && pre < y.length && x[pre] === y[pre]) pre++;
  let suf = 0;
  while (suf < x.length - pre && suf < y.length - pre && x[x.length - 1 - suf] === y[y.length - 1 - suf]) suf++;
  const xs = x.slice(pre, x.length - suf), ys = y.slice(pre, y.length - suf);
  const out = x.slice(0, pre).map((line) => ({ op: ' ', line }));
  if (xs.length * ys.length > 4e6) {
    xs.forEach((line) => out.push({ op: '-', line }));
    ys.forEach((line) => out.push({ op: '+', line }));
  } else {
    const n = xs.length, m = ys.length;
    const t = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) {
      t[i][j] = xs[i] === ys[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
    }
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (xs[i] === ys[j]) { out.push({ op: ' ', line: xs[i] }); i++; j++; }
      else if (t[i + 1][j] >= t[i][j + 1]) out.push({ op: '-', line: xs[i++] });
      else out.push({ op: '+', line: ys[j++] });
    }
    while (i < n) out.push({ op: '-', line: xs[i++] });
    while (j < m) out.push({ op: '+', line: ys[j++] });
  }
  x.slice(x.length - suf).forEach((line) => out.push({ op: ' ', line }));
  return out;
}

// diffView renders a diff with three lines of context around changes.
export function diffView(a, b) {
  const d = diffLines(a, b);
  const keep = new Array(d.length).fill(false);
  d.forEach((e, i) => {
    if (e.op !== ' ') for (let k = Math.max(0, i - 3); k <= Math.min(d.length - 1, i + 3); k++) keep[k] = true;
  });
  const box = h('div', { class: 'diff', role: 'region', 'aria-label': 'Changes', tabindex: '0' });
  let gap = false, adds = 0, dels = 0;
  d.forEach((e, i) => {
    if (e.op === '+') adds++;
    if (e.op === '-') dels++;
    if (!keep[i]) { gap = true; return; }
    if (gap) { box.append(h('div', { class: 'gap' }, '⋯')); gap = false; }
    const cls = e.op === '+' ? 'add' : e.op === '-' ? 'del' : 'ctx';
    box.append(h('div', { class: cls }, (e.op === ' ' ? '  ' : e.op + ' ') + e.line));
  });
  return { el: box, adds, dels };
}
