// Configuration: a structured editor for the common server.conf settings
// and the raw file, both validated by the server and applied with a
// restart.
import { h, icon, api, toast, field, checkbox, select, banner, loading, busy, confirmDialog, APIError } from '../lib.js';
import { reviewAndApply } from '../apply.js';

const CIPHERS = ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305', 'AES-256-CBC', 'AES-192-CBC', 'AES-128-CBC', 'BF-CBC'];
const DIGESTS = [['', 'SHA1 (default)'], 'SHA224', 'SHA256', 'SHA384', 'SHA512'];
const COMPRESSION = [['', 'None (clients that compress are migrated)'], ['compress stub-v2', 'compress stub-v2 (framing only)'], ['compress stub', 'compress stub (framing only)'],
  ['compress lz4-v2', 'compress lz4-v2'], ['compress lz4', 'compress lz4'], ['compress lzo', 'compress lzo'], ['comp-lzo no', 'comp-lzo no (framing only, OpenVPN 2.3)'], ['comp-lzo yes', 'comp-lzo yes (OpenVPN 2.3)'], ['compress migrate', 'compress migrate']];

export async function configPage(main, app) {
  const head = h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Configuration'), h('p', null, 'server.conf: changes are validated, saved and applied by restarting the VPN server.')));
  const banners = h('div');
  const tabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Editor' });
  const panel = h('div');
  main.append(head, banners, tabs, panel);
  panel.append(loading());

  let cfg; // GET /config
  try {
    cfg = await api('GET', '/config');
  } catch (e) {
    panel.replaceChildren(banner('danger', 'Could not load the configuration', e.message));
    return;
  }
  const ro = !cfg.writable;
  if (ro) banners.append(banner('info', 'Editing is disabled', cfg.reason));
  if (cfg.args.length) {
    banners.append(banner('info', 'The command line adds directives', [
      'These apply on top of the file and cannot be changed here: ', h('code', null, cfg.args.join(' ')),
    ]));
  }

  let tab = (location.hash.split('/')[2] || 'settings');
  let settingsView = null, rawView = null;
  const tabButtons = [['settings', 'Settings'], ['raw', 'File (server.conf)']].map(([t, label]) =>
    h('button', { type: 'button', role: 'tab', id: 'tab-' + t, 'aria-controls': 'panel', dataset: { tab: t }, onclick: () => show(t) }, label));
  tabs.append(...tabButtons);
  panel.id = 'panel';
  panel.setAttribute('role', 'tabpanel');

  function show(t, opts = {}) {
    if (t === 'raw' && settingsView && settingsView.dirty() && !opts.text) {
      // carry unsaved structured edits over? keep it simple: ask.
      if (!confirm('Discard the unsaved changes in Settings?')) return;
      settingsView = null;
    }
    if (t === 'settings' && rawView && rawView.dirty()) {
      if (!confirm('Discard the unsaved changes to the file?')) return;
      rawView = null;
    }
    tab = t;
    tabButtons.forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === t)));
    history.replaceState(null, '', '#/config/' + t);
    if (t === 'raw') {
      rawView = rawEditor(app, cfg, ro, reload, opts);
      panel.replaceChildren(rawView.el);
    } else {
      settingsView = settingsEditor(app, cfg, ro, reload, (text, errors) => show('raw', { text, errors }));
      panel.replaceChildren(settingsView.el);
    }
  }

  async function reload() {
    cfg = await api('GET', '/config');
    settingsView = rawView = null;
    show(tab);
  }

  app.guard = () => {
    const v = tab === 'raw' ? rawView : settingsView;
    return v && v.dirty() ? 'You have unsaved configuration changes. Leave this page and lose them?' : null;
  };
  show(tab === 'raw' ? 'raw' : 'settings');
  const onKey = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      const v = tab === 'raw' ? rawView : settingsView;
      if (v && !ro) v.save();
    }
  };
  document.addEventListener('keydown', onKey);
  return () => document.removeEventListener('keydown', onKey);
}

// ---- raw editor ----

function rawEditor(app, cfg, ro, reload, opts) {
  const ta = h('textarea', { spellcheck: 'false', autocapitalize: 'none', autocomplete: 'off', wrap: 'off', 'aria-label': 'server.conf', readOnly: ro });
  ta.value = opts.text != null ? opts.text : cfg.text;
  const gutter = h('div', { class: 'gutter', 'aria-hidden': 'true' });
  const issuesBox = h('div', { class: 'issues', 'aria-live': 'polite' });
  const state = h('span', { class: 'status' });
  let errorLines = new Set();
  let checkTimer = null, seq = 0;

  const paintGutter = () => {
    const n = ta.value.split('\n').length;
    const frag = [];
    for (let i = 1; i <= n; i++) frag.push(errorLines.has(i) ? h('span', { class: 'err' }, String(i)) : String(i), '\n');
    gutter.replaceChildren(...frag);
    gutter.scrollTop = ta.scrollTop;
  };
  const dirty = () => ta.value !== cfg.text;
  const paintState = () => {
    state.className = 'status' + (dirty() ? ' dirty' : '');
    state.replaceChildren(dirty() ? 'Unsaved changes' : 'No changes');
  };
  const goLine = (n) => {
    const lines = ta.value.split('\n');
    let start = 0;
    for (let i = 0; i < n - 1 && i < lines.length; i++) start += lines[i].length + 1;
    ta.focus();
    ta.setSelectionRange(start, start + (lines[n - 1] || '').length);
    const lh = parseFloat(getComputedStyle(ta).lineHeight) || 20;
    ta.scrollTop = Math.max(0, (n - 5) * lh);
  };
  const showIssues = (errs, okText) => {
    errorLines = new Set(errs.filter((e) => e.line).map((e) => e.line));
    paintGutter();
    issuesBox.className = 'issues' + (errs.length ? '' : ' ok');
    issuesBox.replaceChildren(...(errs.length ? errs.map((e) => h('div', { class: 'issue' },
      e.line ? h('button', { type: 'button', onclick: () => goLine(e.line) }, 'Line ' + e.line) : icon('alert'),
      h('span', null, e.message))) : okText ? [h('div', { class: 'issue' }, icon('check'), h('span', null, okText))] : []));
  };
  const check = async (explicit) => {
    const my = ++seq;
    try {
      const r = await api('POST', '/config/check', { text: ta.value });
      if (my !== seq) return r;
      showIssues(r.errors, explicit || dirty() ? 'The configuration is valid.' : '');
      return r;
    } catch (e) {
      if (my === seq) showIssues([{ line: 0, message: e.message }]);
      return null;
    }
  };
  ta.addEventListener('scroll', () => { gutter.scrollTop = ta.scrollTop; });
  ta.addEventListener('input', () => {
    paintGutter(); paintState();
    clearTimeout(checkTimer);
    checkTimer = setTimeout(() => check(false), 700);
  });
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Tab' && !e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey && !ro && e.target === ta && ta.dataset.tabIndent === '1') {
      e.preventDefault();
      ta.setRangeText('\t', ta.selectionStart, ta.selectionEnd, 'end');
    }
  });

  const save = async () => {
    if (ro) return;
    if (!dirty()) { toast('ok', 'Nothing to save', 'The file has not changed.'); return; }
    const r = await check(true);
    if (!r) return;
    if (!r.ok) { toast('error', 'Not saved: the configuration has problems', 'Fix the lines marked below.'); return; }
    const res = await reviewAndApply(app, cfg.text, ta.value, cfg.hash);
    if (!res) return;
    if (res.ok) { await reload(); return; }
    showIssues(res.errors || [{ line: 0, message: res.message }]);
  };
  const saveBtn = h('button', { type: 'button', class: 'btn primary', disabled: ro, onclick: (e) => busy(e.currentTarget, save) }, icon('refresh'), 'Save and apply');
  const checkBtn = h('button', { type: 'button', class: 'btn', onclick: (e) => busy(e.currentTarget, () => check(true)) }, icon('check'), 'Check');
  const revert = h('button', { type: 'button', class: 'btn ghost', disabled: ro, onclick: async () => {
    if (dirty() && !await confirmDialog({ title: 'Revert your changes?', message: 'The editor goes back to the file as it is on disk.', confirm: 'Revert', tone: 'warn', iconName: 'refresh' })) return;
    ta.value = cfg.text; paintGutter(); paintState(); showIssues([]);
  } }, 'Revert');
  paintGutter(); paintState();
  if (opts.errors) showIssues(opts.errors);
  else if (opts.text != null) check(true);

  const el = h('div', null,
    h('section', { class: 'card' },
      h('div', { class: 'card-head' },
        h('div', null, h('h2', null, cfg.file || 'server.conf'),
          h('p', null, 'Comments, order and inline blocks are kept exactly as you write them. Ctrl+S saves.')),
        ro ? h('span', { class: 'badge' }, 'read-only') : null),
      h('div', { class: 'card-body' }, h('div', { class: 'editor' }, gutter, ta), issuesBox)),
    ro ? null : h('div', { class: 'savebar' }, state, revert, checkBtn, saveBtn));
  return { el, dirty, save };
}

// ---- structured editor ----

function settingsEditor(app, cfg, ro, reload, toRaw) {
  const s = JSON.parse(JSON.stringify(cfg.settings)); // edited copy
  const orig = JSON.stringify(cfg.settings);
  const dirty = () => JSON.stringify(s) !== orig;
  const state = h('span', { class: 'status' });
  const errBox = h('div');
  const paint = () => {
    state.className = 'status' + (dirty() ? ' dirty' : '');
    state.replaceChildren(dirty() ? 'Unsaved changes' : 'No changes');
  };
  const onChange = () => paint();

  // Generic controls bound to s[key].
  const text = (key, attrs = {}) => {
    const el = h('input', Object.assign({ type: 'text', value: s[key] || '', spellcheck: 'false', disabled: ro }, attrs));
    el.addEventListener('input', () => { s[key] = el.value; onChange(); });
    return el;
  };
  const num = (key, attrs = {}) => text(key, Object.assign({ inputmode: 'numeric' }, attrs));
  const bool = (key, label, hint) => {
    const c = checkbox(label, !!s[key], hint, (e) => { s[key] = e.target.checked; onChange(); });
    c.input.disabled = ro;
    return c.el;
  };
  const choice = (key, options) => {
    const el = select(options, s[key] || '', { disabled: ro });
    el.addEventListener('change', () => { s[key] = el.value; onChange(); });
    return el;
  };
  const lines = (key, attrs = {}) => {
    const el = h('textarea', Object.assign({ rows: '3', spellcheck: 'false', disabled: ro }, attrs));
    el.value = (s[key] || []).join('\n');
    el.addEventListener('input', () => { s[key] = el.value.split('\n').map((x) => x.trim()).filter(Boolean); onChange(); });
    return el;
  };
  const section = (id, title, sub, ...children) => h('section', { class: 'card section', id: 'sec-' + id, 'aria-labelledby': 'h-' + id },
    h('div', { class: 'card-head' }, h('div', null, h('h2', { id: 'h-' + id }, title), sub ? h('p', null, sub) : null)),
    h('div', { class: 'card-body' }, children));

  // ---- network ----
  const protoBox = h('div', { class: 'chips' });
  const protoSet = new Set((s.proto || []).map((p) => p.replace(/-server$/, '')));
  const paintProto = () => {
    protoBox.replaceChildren();
    const opts = ['udp', 'tcp', 'udp4', 'tcp4', 'udp6', 'tcp6'].filter((p) => p.length === 3 || protoSet.has(p));
    for (const p of opts) {
      const c = checkbox(p.toUpperCase().replace(/(\d)$/, ' (IPv$1)'), protoSet.has(p), null, (e) => {
        if (e.target.checked) protoSet.add(p); else protoSet.delete(p);
        // keep the file's order for the ones that stay
        const order = (cfg.settings.proto || []).filter((x) => protoSet.has(x));
        for (const x of protoSet) if (!order.includes(x)) order.push(x);
        s.proto = order;
        onChange();
      });
      c.input.disabled = ro;
      protoBox.append(c.el);
    }
  };
  paintProto();
  const devSeg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Device type' });
  for (const [v, label] of [['tun', 'TUN (routed)'], ['tap', 'TAP (bridged)']]) {
    const b = h('button', { type: 'button', 'aria-pressed': String(s.dev === v), disabled: ro }, label);
    b.addEventListener('click', () => {
      s.dev = v; onChange();
      devSeg.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    });
    devSeg.append(b);
  }
  const network = section('network', 'Network', 'Where clients connect, and the addresses inside the tunnel.',
    h('div', { class: 'fields' },
      field('Port', num('port', { placeholder: '1194' })),
      h('div', { class: 'field' }, h('span', { class: 'label' }, 'Protocols'), protoBox, h('div', { class: 'hint' }, 'softvpn can listen on UDP and TCP at once.')),
      h('div', { class: 'field' }, h('span', { class: 'label' }, 'Mode'), devSeg, h('div', { class: 'hint' }, 'TAP needs dev tap in client profiles too; IPv6 and routes are TUN only.'))),
    h('div', { class: 'fields' },
      field('IPv4 subnet', text('server', { placeholder: '10.8.0.0/24' }), 'Clients get addresses from this network; the server is .1.'),
      field('IPv6 subnet', text('serverIPv6', { placeholder: 'fd00:8::/64 (off when empty)' }), 'Turns on IPv6 inside the tunnel.')),
    field('Networks inside the VPN (route / route-ipv6)', lines('routes', { placeholder: '192.168.10.0/24' }), 'Networks behind clients (each needs an iroute in its client settings). One prefix per line.'));

  // ---- pushed options ----
  const push = pushModel(s.push || []);
  const commitPush = () => { s.push = push.compose(); onChange(); };
  const redirect = checkbox('Send all client traffic through the VPN', push.redirect.on, 'push "redirect-gateway def1": the server NATs it out to the internet.', (e) => {
    push.redirect.on = e.target.checked; redirect6.input.disabled = ro || !e.target.checked; commitPush();
  });
  const redirect6 = checkbox('Also IPv6 traffic', push.redirect.ipv6, 'Adds "ipv6" (needs an IPv6 subnet).', (e) => { push.redirect.ipv6 = e.target.checked; commitPush(); });
  redirect.input.disabled = ro;
  redirect6.input.disabled = ro || !push.redirect.on;
  const dns = h('textarea', { rows: '2', spellcheck: 'false', disabled: ro, placeholder: '10.8.0.1' });
  dns.value = push.dns.join('\n');
  dns.addEventListener('input', () => { push.dns = dns.value.split(/[\s,]+/).filter(Boolean); commitPush(); });
  const domain = h('input', { type: 'text', value: push.domain, spellcheck: 'false', disabled: ro, placeholder: 'example.internal' });
  domain.addEventListener('input', () => { push.domain = domain.value.trim(); commitPush(); });
  const others = h('textarea', { rows: '4', spellcheck: 'false', disabled: ro, placeholder: 'route 10.20.0.0 255.255.0.0' });
  others.value = push.other.join('\n');
  others.addEventListener('input', () => { push.other = others.value.split('\n').map((x) => x.trim()).filter(Boolean); commitPush(); });
  const gw = app.status && app.status.gateway;
  const pushed = section('push', 'Pushed to clients', 'Options every client receives when it connects (push "...").',
    redirect.el, h('div', { class: 'check-indent' }, redirect6.el),
    h('div', { class: 'fields' },
      field('DNS servers', dns, gw ? `One per line. ${gw} is the server itself: it relays DNS to the host's resolver.` : 'One per line.'),
      field('DNS search domain', domain, 'dhcp-option DOMAIN')),
    field('Other options', others, 'One option per line, without "push" and quotes, e.g. route 10.20.0.0 255.255.0.0'));

  // ---- clients ----
  const clients = section('clients', 'Clients', null,
    bool('clientToClient', 'Clients can reach each other (client-to-client)', 'Also needed for networks behind clients.'),
    bool('duplicateCN', 'Allow several connections with the same certificate (duplicate-cn)'),
    h('div', { class: 'fields' },
      field('Keepalive interval (s)', num('keepaliveInterval', { placeholder: '10' }), 'keepalive: ping after this much silence.'),
      field('Keepalive timeout (s)', num('keepaliveTimeout', { placeholder: '60' }), 'Clients restart after this much silence.'),
      field('Maximum clients', num('maxClients', { placeholder: 'unlimited' }))),
    field('Client settings directory (client-config-dir)', text('clientConfigDir', { placeholder: 'ccd' }),
      'Per-client files (static addresses, iroutes). Relative to server.conf; created if it does not exist.'));

  // ---- encryption ----
  const cipherBox = h('div', { class: 'list-editor' });
  const useDefault = checkbox('Use the default list (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305)', !(s.dataCiphers && s.dataCiphers.length), null, (e) => {
    s.dataCiphers = e.target.checked ? [] : ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'];
    paintCiphers(); onChange();
  });
  useDefault.input.disabled = ro;
  const paintCiphers = () => {
    cipherBox.replaceChildren();
    if (!s.dataCiphers.length) return;
    const order = s.dataCiphers.concat(CIPHERS.filter((c) => !s.dataCiphers.includes(c)));
    order.forEach((c) => {
      const on = s.dataCiphers.includes(c);
      const i = s.dataCiphers.indexOf(c);
      const cb = h('input', { type: 'checkbox', checked: on, disabled: ro, 'aria-label': c });
      cb.addEventListener('change', () => {
        s.dataCiphers = cb.checked ? s.dataCiphers.concat(c) : s.dataCiphers.filter((x) => x !== c);
        if (!s.dataCiphers.length) { useDefault.input.checked = true; }
        paintCiphers(); onChange();
      });
      const move = (d) => {
        const a = s.dataCiphers.slice();
        [a[i], a[i + d]] = [a[i + d], a[i]];
        s.dataCiphers = a; paintCiphers(); onChange();
        cipherBox.querySelector(`[data-c="${c}"][data-d="${d}"]`)?.focus();
      };
      cipherBox.append(h('div', { class: 'item' },
        h('label', { class: 'check' }, cb, h('span', { class: 'mono' }, c, /CBC/.test(c) ? h('small', null, 'for older clients') : null)),
        on ? h('span', { class: 'row-actions' },
          h('button', { type: 'button', class: 'btn sm ghost icon-only', disabled: ro || i === 0, 'aria-label': `Move ${c} up`, title: 'Prefer it more', dataset: { c, d: '-1' }, onclick: () => move(-1) }, '↑'),
          h('button', { type: 'button', class: 'btn sm ghost icon-only', disabled: ro || i === s.dataCiphers.length - 1, 'aria-label': `Move ${c} down`, title: 'Prefer it less', dataset: { c, d: '1' }, onclick: () => move(1) }, '↓')) : null));
    });
  };
  paintCiphers();
  const encryption = section('crypto', 'Encryption', 'Data-channel ciphers, in order of preference.',
    useDefault.el, cipherBox,
    h('div', { class: 'fields' },
      field('Fallback cipher', choice('cipherFallback', [['', 'none']].concat(CIPHERS)), 'data-ciphers-fallback: for clients that cannot negotiate (OpenVPN 2.3, --ncp-disable).'),
      field('HMAC digest (auth)', choice('auth', DIGESTS), 'For CBC ciphers and tls-auth; clients need the same.'),
      field('Compression', choice('compression', COMPRESSION), 'Pushed to clients. Compression enables VORACLE-style attacks; prefer none.'),
      field('allow-compression', choice('allowCompression', [['', 'asym (default): accept, never send compressed'], ['no', 'no: framing only'], ['yes', 'yes: also compress what the server sends']]))));

  // ---- authentication ----
  const auth = section('auth', 'Authentication', 'How clients prove who they are.',
    h('div', { class: 'fields' },
      field('Client certificates (verify-client-cert)', choice('verifyClientCert', [['', 'Required (default)'], ['optional', 'Optional: a password is enough'], ['none', 'Not used: passwords only']])),
      field('Users file (auth-user-pass-file)', text('authUserPassFile', { placeholder: 'off when empty, e.g. users' }), 'Built-in username/password database. Created empty if missing.'),
      field('Revocation list (crl-verify)', text('crlVerify', { placeholder: 'e.g. /pki/crl.pem' }), app.status && app.status.pki.dir ? `The web UI revokes into ${app.status.pki.dir}/crl.pem.` : 'PEM or DER CRL.')),
    bool('authUserPassOptional', 'Clients with a certificate need no password (auth-user-pass-optional)'),
    bool('usernameAsCommonName', 'Name sessions after the username (username-as-common-name)', 'Also selects the client settings file by username.'),
    h('div', { class: 'fields' },
      h('div', { class: 'field' }, bool('authGenToken', 'Issue auth tokens (auth-gen-token)', 'Clients renegotiate and reconnect with a token instead of the password.')),
      field('Token lifetime (s)', num('authGenTokenLifetime', { placeholder: 'until restart' }))));

  // ---- control channel ----
  const wrapFile = text('tlsWrapFile', { placeholder: s.tlsWrapInline ? 'inline key in server.conf' : 'key file' });
  const genBtn = h('button', { type: 'button', class: 'btn', disabled: ro || !s.tlsWrap || !(app.status && app.status.pki.writable) }, icon('wand'), 'Generate key');
  const keyDir = choice('keyDirection', [['', 'none (bidirectional)'], ['0', '0 (server; clients use 1)'], ['1', '1']]);
  const keyDirField = field('Key direction', keyDir, 'tls-auth only. Profiles from this UI match it.');
  const wrapMode = select([['', 'None: TLS only'], ['tls-auth', 'tls-auth: HMAC on control packets'], ['tls-crypt', 'tls-crypt: encrypted control channel'], ['tls-crypt-v2', 'tls-crypt-v2: per-client keys']], s.tlsWrap || '', { disabled: ro });
  const paintWrap = () => {
    genBtn.disabled = ro || !s.tlsWrap || !(app.status && app.status.pki.writable);
    keyDirField.hidden = s.tlsWrap !== 'tls-auth';
    wrapFile.disabled = ro || !s.tlsWrap;
  };
  wrapMode.addEventListener('change', () => {
    const was = cfg.settings.tlsWrap;
    s.tlsWrap = wrapMode.value;
    if (s.tlsWrap !== was) { s.tlsWrapInline = false; s.tlsWrapFile = ''; wrapFile.value = ''; wrapFile.placeholder = 'key file'; }
    else { s.tlsWrapInline = cfg.settings.tlsWrapInline; s.tlsWrapFile = cfg.settings.tlsWrapFile; wrapFile.value = s.tlsWrapFile; }
    if (s.tlsWrap === 'tls-auth' && !s.keyDirection) { s.keyDirection = '0'; keyDir.value = '0'; }
    paintWrap(); onChange();
  });
  genBtn.addEventListener('click', () => busy(genBtn, async () => {
    try {
      const r = await api('POST', '/keys/' + s.tlsWrap, {});
      s.tlsWrapFile = r.file; wrapFile.value = r.file; onChange();
      toast('ok', r.created ? 'Key created' : 'Using the existing key', r.file);
    } catch (e) { toast('error', 'Could not create the key', e.message); }
  }));
  paintWrap();
  const wrap = section('wrap', 'Control channel', 'Extra protection for the TLS handshake. Every client profile must be downloaded again after a change.',
    h('div', { class: 'fields' },
      field('Protection', wrapMode),
      h('div', { class: 'field' }, h('label', { for: wrapFile.id || (wrapFile.id = 'wrap-file') }, 'Key file'), h('div', { class: 'input-row' }, wrapFile, genBtn)),
      keyDirField));

  // ---- advanced ----
  const advanced = section('advanced', 'Advanced', null,
    h('div', { class: 'fields' },
      field('Upstream DNS', text('upstreamDNS', { placeholder: 'from /etc/resolv.conf' }), 'Where DNS sent to the gateway is relayed (softvpn).'),
      field('Log verbosity (verb)', num('verb', { placeholder: '1' }), '0 warnings only, 3 normal, 4+ debug.'),
      field('tun-mtu', num('tunMTU', { placeholder: '1500' }))),
    h('div', { class: 'fields' },
      field('NAT allow list (nat-allow)', lines('natAllow', { placeholder: 'everything when empty' }), 'Destinations clients may reach through the NAT; one prefix per line.'),
      field('NAT deny list (nat-deny)', lines('natDeny'), 'Always refused; loopback, link-local and the VPN subnet are refused anyway.')));

  const save = async () => {
    if (ro) return;
    errBox.replaceChildren();
    if (!dirty()) { toast('ok', 'Nothing to save', 'No setting has changed.'); return; }
    let r;
    try {
      r = await api('POST', '/config/render', { settings: s, hash: cfg.hash });
    } catch (e) {
      if (e instanceof APIError && e.status === 409) {
        errBox.append(banner('warn', 'The file changed on disk', 'Someone edited server.conf since this page loaded.',
          h('button', { type: 'button', class: 'btn sm', onclick: () => reload() }, 'Reload')));
      } else errBox.append(banner('danger', 'These settings cannot be saved', e.message));
      errBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }
    if (!r.changed) { toast('ok', 'Nothing to save', 'The file already has these settings.'); return; }
    const check = await api('POST', '/config/check', { text: r.text });
    if (!check.ok) { showErrors(check.errors, r.text); return; }
    const res = await reviewAndApply(app, cfg.text, r.text, cfg.hash);
    if (!res) return;
    if (res.ok) { await reload(); return; }
    showErrors(res.errors || [{ line: 0, message: res.message }], r.text);
  };
  const showErrors = (errs, text) => {
    errBox.replaceChildren(h('div', { class: 'banner danger', role: 'alert' }, icon('alert'), h('div', null,
      h('strong', null, 'Not saved: the server would reject this configuration'),
      errs.map((e) => h('p', null, (e.line ? `Line ${e.line}: ` : '') + e.message))),
      h('button', { type: 'button', class: 'btn sm', onclick: () => toRaw(text, errs) }, 'Fix in the file editor')));
    errBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
  };
  const saveBtn = h('button', { type: 'button', class: 'btn primary', disabled: ro, onclick: (e) => busy(e.currentTarget, save) }, icon('refresh'), 'Review and apply');
  const discard = h('button', { type: 'button', class: 'btn ghost', disabled: ro, onclick: async () => {
    if (dirty() && !await confirmDialog({ title: 'Discard your changes?', message: 'The settings go back to what the file says.', confirm: 'Discard', tone: 'warn', iconName: 'refresh' })) return;
    reload();
  } }, 'Discard');
  paint();
  const el = h('div', null, errBox, h('div', { class: 'stack' }, network, pushed, clients, encryption, auth, wrap, advanced),
    ro ? null : h('div', { class: 'savebar' }, state, discard, saveBtn));
  return { el, dirty, save };
}

// pushModel splits the push list into what the form edits (redirect-gateway,
// DNS servers, search domain) and everything else, and puts it back
// together in the original order.
function pushModel(list) {
  const kind = (o) => {
    if (/^redirect-gateway\b/i.test(o)) return 'redirect';
    if (/^dhcp-option\s+DNS6?\s+/i.test(o)) return 'dns';
    if (/^dhcp-option\s+DOMAIN\s+/i.test(o)) return 'domain';
    return 'other';
  };
  const rg = list.find((o) => kind(o) === 'redirect');
  const m = {
    redirect: { on: !!rg, ipv6: !!rg && /\bipv6\b/.test(rg), flags: rg ? rg.split(/\s+/).slice(1).filter((f) => f !== 'ipv6' && f !== 'def1') : [] },
    dns: list.filter((o) => kind(o) === 'dns').map((o) => o.split(/\s+/)[2]),
    domain: (list.find((o) => kind(o) === 'domain') || '').split(/\s+/)[2] || '',
    other: list.filter((o) => kind(o) === 'other'),
  };
  const orig = { redirect: rg, dns: list.filter((o) => kind(o) === 'dns'), domain: list.filter((o) => kind(o) === 'domain') };
  m.compose = () => {
    const parts = {
      redirect: m.redirect.on ? [rg && m.redirect.ipv6 === /\bipv6\b/.test(rg) ? rg : ['redirect-gateway', 'def1', ...m.redirect.flags, m.redirect.ipv6 ? 'ipv6' : null].filter(Boolean).join(' ')] : [],
      dns: m.dns.map((ip, i) => orig.dns[i] && orig.dns[i].split(/\s+/)[2] === ip ? orig.dns[i] : `dhcp-option ${ip.includes(':') ? 'DNS6' : 'DNS'} ${ip}`),
      domain: m.domain ? [orig.domain[0] && orig.domain[0].split(/\s+/)[2] === m.domain ? orig.domain[0] : `dhcp-option DOMAIN ${m.domain}`] : [],
      other: m.other,
    };
    const out = [], seen = new Set();
    for (const o of list) {
      const k = kind(o);
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(...parts[k]);
    }
    for (const k of ['redirect', 'dns', 'domain', 'other']) if (!seen.has(k)) out.push(...parts[k]);
    return out;
  };
  return m;
}
