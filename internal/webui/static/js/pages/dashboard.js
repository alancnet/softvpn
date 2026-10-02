// Dashboard: server status and the connected clients, updated live.
import { h, icon, api, toast, confirmDialog, bytes, duration, dateTime, banner, empty } from '../lib.js';

export async function dashboardPage(main, app) {
  const head = h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Dashboard'), h('p', null, 'The server and who is connected right now.')),
    h('div', { class: 'page-actions' }, h('span', { class: 'badge info pulse', title: 'This page updates itself' }, 'Live')));
  const banners = h('div');
  const stats = h('div', { class: 'grid stats' });
  const sessionsCard = h('section', { class: 'card', 'aria-labelledby': 'sess-title' });
  const details = h('div', { class: 'grid two' });
  main.append(head, banners, stats, h('div', { class: 'stack' }, sessionsCard, details));

  let prev = new Map(); // id -> {rx, tx, t} for rates
  let rates = new Map();

  function renderStatic(s) {
    banners.replaceChildren();
    if (!s) return;
    if (!s.running) banners.append(banner('danger', 'The VPN server is not running', 'It may be restarting with a new configuration. This page updates when it is back.'));
    if (!s.config.writable) banners.append(banner('info', 'Read-only mode', s.config.reason));
    if (s.webui.http) banners.append(banner('warn', 'The web UI is served over plain HTTP', 'web-ui-http is set: make sure a TLS reverse proxy sits in front of it.'));

    details.replaceChildren(
      h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('h2', null, 'Server')),
        h('div', { class: 'card-body' }, h('dl', { class: 'kv' },
          kv('Version', s.version),
          kv('Process up', duration(Date.now() - new Date(s.processStarted).getTime())),
          kv('Engine started', dateTime(s.engineStarted)),
          kv('Configuration applied', s.lastApplied ? dateTime(s.lastApplied) : 'not since start'),
          kv('Config file', s.config.file ? h('code', null, s.config.file) : '—'),
          s.config.args.length ? kv('Command line', h('code', null, s.config.args.join(' '))) : null,
        ))),
      h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('h2', null, 'Security')),
        h('div', { class: 'card-body' }, h('dl', { class: 'kv' },
          kv('Client certificates', { require: 'required', optional: 'optional', none: 'not used' }[s.auth.verifyClientCert] || s.auth.verifyClientCert || '—'),
          kv('Password users', s.auth.usersFile ? h('code', null, s.auth.usersFile) : 'off'),
          kv('Revocation (CRL)', s.auth.crlFile ? h('code', null, s.auth.crlFile) : h('span', { class: 'badge warn' }, 'not checked')),
          kv('Control channel', s.wrap || 'TLS only'),
          kv('Data ciphers', h('div', { class: 'chips' }, s.ciphers.map((c) => h('span', { class: 'chip' }, c)))),
          kv('Compression', s.compress || 'none'),
        ))));
  }

  function kv(k, v) { return [h('dt', null, k), h('dd', null, v)]; }

  function renderStats(s, live) {
    if (!s) { stats.replaceChildren(); return; }
    const running = live ? live.running : s.running;
    const n = live ? live.sessions.length : s.clients;
    const started = (live && live.engineStarted) || s.engineStarted;
    const totals = (live ? live.sessions : []).reduce((a, x) => [a[0] + x.rxBytes, a[1] + x.txBytes], [0, 0]);
    stats.replaceChildren(
      stat('activity', 'Status', running ? h('span', { class: 'badge ok' }, 'Running') : h('span', { class: 'badge danger' }, 'Stopped'),
        running && started ? 'up ' + duration(Date.now() - new Date(started).getTime()) : 'restarting…'),
      stat('clients', 'Connected', String(n), s.maxClients ? `of at most ${s.maxClients}` : `${bytes(totals[0])} in · ${bytes(totals[1])} out`),
      stat('globe', 'Network', s.subnet || '—', [s.subnet6, s.mode === 'tap' ? 'TAP (bridged)' : 'TUN (routed)'].filter(Boolean).join(' · ')),
      stat('plug', 'Listening', s.listeners.map((l) => l.proto.toUpperCase()).join(' + ') || '—', s.listeners.map((l) => l.addr).join(', ')));
  }

  function stat(ic, label, value, sub) {
    return h('div', { class: 'card stat' },
      h('div', { class: 'stat-label' }, icon(ic), label),
      h('div', { class: 'stat-value' }, value),
      sub ? h('div', { class: 'stat-sub' }, sub) : null);
  }

  function renderSessions(live) {
    const list = live ? live.sessions : [];
    const now = Date.now();
    const next = new Map();
    for (const s of list) {
      const p = prev.get(s.id);
      if (p && now > p.t) {
        rates.set(s.id, { rx: Math.max(0, (s.rxBytes - p.rx) * 1000 / (now - p.t)), tx: Math.max(0, (s.txBytes - p.tx) * 1000 / (now - p.t)) });
      }
      next.set(s.id, { rx: s.rxBytes, tx: s.txBytes, t: now });
    }
    prev = next;
    const headEl = h('div', { class: 'card-head' },
      h('div', null, h('h2', { id: 'sess-title' }, 'Connected clients'), h('p', null, list.length ? `${list.length} session${list.length === 1 ? '' : 's'}` : 'Nobody is connected.')));
    if (!list.length) {
      sessionsCard.replaceChildren(headEl, empty('clients', 'No clients connected', 'Clients appear here as soon as they connect.'));
      return;
    }
    const tbody = h('tbody');
    for (const s of list) {
      const r = rates.get(s.id);
      const who = s.username && s.username !== s.commonName ? `${s.commonName} (user ${s.username})` : s.commonName;
      tbody.append(h('tr', null,
        h('td', { class: 'primary-cell' }, h('div', { class: 'cell-main' }, who || '—'),
          h('div', { class: 'cell-sub' }, s.remote.replace(/^(udp|tcp):/, (m, p) => p.toUpperCase() + ' '))),
        h('td', { 'data-label': 'VPN address' }, h('div', { class: 'mono' }, s.ip), s.ip6 ? h('div', { class: 'cell-sub mono' }, s.ip6) : null),
        h('td', { 'data-label': 'Client' }, h('div', null, s.version ? 'OpenVPN ' + s.version : 'unknown'), h('div', { class: 'cell-sub' }, [s.platform, s.cipher].filter(Boolean).join(' · '))),
        h('td', { 'data-label': 'Traffic', class: 'num' },
          h('div', { class: 'nowrap' }, '↓ ' + bytes(s.rxBytes), '  ↑ ' + bytes(s.txBytes)),
          r ? h('div', { class: 'rate nowrap' }, `${bytes(r.rx)}/s · ${bytes(r.tx)}/s`) : null),
        h('td', { 'data-label': 'Connected', class: 'nowrap' }, duration(now - new Date(s.since).getTime())),
        h('td', { class: 'actions-cell' }, h('div', { class: 'row-actions' },
          h('button', { type: 'button', class: 'btn sm', title: 'Tell the client to reconnect', dataset: { key: 'r' + s.id }, onclick: () => kick(s, true) }, icon('refresh'), 'Reconnect'),
          h('button', { type: 'button', class: 'btn sm ghost danger-text', title: 'Disconnect this client', dataset: { key: 'd' + s.id }, onclick: () => kick(s, false) }, icon('power'), 'Disconnect')))));
    }
    // Keep keyboard focus across the live re-render.
    const focused = sessionsCard.contains(document.activeElement) && document.activeElement.dataset.key;
    sessionsCard.replaceChildren(headEl, h('div', { class: 'table-wrap' }, h('table', { class: 'data stackable' },
      h('thead', null, h('tr', null, ['Client', 'VPN address', 'Software', 'Traffic', 'Connected', ''].map((t) => h('th', { scope: 'col' }, t)))),
      tbody)));
    if (focused) {
      const el = sessionsCard.querySelector(`[data-key="${focused}"]`);
      if (el) el.focus();
    }
  }

  async function kick(s, reconnect) {
    const ok = await confirmDialog(reconnect ? {
      title: `Reconnect ${s.commonName}?`, confirm: 'Reconnect', tone: 'warn', iconName: 'refresh',
      message: 'The client is told to reconnect. It comes back within seconds and picks up any change to its settings.',
    } : {
      title: `Disconnect ${s.commonName}?`, confirm: 'Disconnect',
      message: 'The client is told to exit. A stock OpenVPN client stays disconnected until its user reconnects; a client set to retry forever may come back. To keep it out, revoke its certificate or delete its user.',
    });
    if (!ok) return;
    try {
      await api('POST', `/sessions/${s.id}/disconnect`, { reconnect });
      toast('ok', reconnect ? `${s.commonName} is reconnecting` : `${s.commonName} disconnected`);
    } catch (e) {
      toast('error', 'Could not disconnect', e.message);
    }
  }

  const onEvent = (kind, data) => {
    if (kind === 'sessions') { renderStats(app.status, data); renderSessions(data); }
    if (kind === 'status') { renderStatic(data); renderStats(data, app.live); }
  };
  app.listeners.add(onEvent);
  renderStatic(app.status);
  renderStats(app.status, app.live);
  renderSessions(app.live);
  const timer = setInterval(() => renderStats(app.status, app.live), 10000);
  return () => { app.listeners.delete(onEvent); clearInterval(timer); };
}
