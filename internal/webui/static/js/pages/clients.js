// Clients: certificates issued from the PKI, their profiles, revocation and
// per-client settings (client-config-dir).
import { h, icon, api, toast, openDialog, confirmDialog, field, checkbox, select, banner, empty, loading, busy, download, dateStr, randomPassword, copyText, APIError } from '../lib.js';
import { changeSettings } from '../apply.js';

export async function clientsPage(main, app) {
  const head = h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Clients'), h('p', null, 'Client certificates, their profiles and per-client settings.')));
  const banners = h('div');
  const body = h('section', { class: 'card' }, loading());
  main.append(head, banners, body);

  let data = null;
  let filter = '';
  let showRevoked = false;
  const search = h('input', { type: 'search', placeholder: 'Filter by name', 'aria-label': 'Filter clients by name' });

  const newBtn = h('button', { type: 'button', class: 'btn primary', onclick: () => newClient() }, icon('plus'), 'New client');
  head.append(h('div', { class: 'page-actions' }, newBtn));

  async function load() {
    try {
      data = await api('GET', '/clients');
      render();
    } catch (e) {
      body.replaceChildren(h('div', { class: 'card-body' }, banner('danger', 'Could not load the clients', e.message)));
    }
  }

  function render() {
    const hadFocus = document.activeElement === search;
    const pki = data.pki;
    banners.replaceChildren();
    newBtn.disabled = !pki.available || !pki.writable;
    newBtn.title = newBtn.disabled ? pki.reason : '';
    if (!pki.available) banners.append(banner('info', 'Client certificates cannot be managed here', pki.reason));
    else if (!pki.writable) banners.append(banner('info', 'The PKI directory is read-only', pki.reason + ' Profiles can still be downloaded.'));
    if (pki.available && !data.crl.configured) {
      const cfgWritable = app.status && app.status.config.writable;
      banners.append(banner('warn', 'Revoked certificates are not refused',
        'The server has no crl-verify, so revoking a certificate here does not keep it out.',
        cfgWritable && data.crl.pkiFile ? h('button', {
          type: 'button', class: 'btn sm',
          onclick: () => changeSettings(app, (s) => { s.crlVerify = data.crl.pkiFile; }, {
            title: 'Enable certificate revocation', intro: 'Adds crl-verify so the server refuses revoked certificates and disconnects them within seconds of being revoked.',
          }).then(load),
        }, 'Enable crl-verify') : null));
    } else if (pki.available && data.crl.matches === false) {
      banners.append(banner('warn', 'The server checks a different CRL', `crl-verify is ${data.crl.file}, but revocations here go to ${data.crl.pkiFile}.`));
    }

    const all = data.clients;
    const revokedCount = all.filter((c) => c.revoked).length;
    search.oninput = () => { filter = search.value; renderTable(); };
    const rev = checkbox(`Show revoked (${revokedCount})`, showRevoked, null, (e) => { showRevoked = e.target.checked; render(); });
    const headEl = h('div', { class: 'card-head' },
      h('div', null, h('h2', null, 'Certificates'), h('p', null, `${all.filter((c) => !c.revoked).length} active` + (revokedCount ? `, ${revokedCount} revoked` : ''))),
      h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search'), search), revokedCount ? rev.el : null));
    const tableBox = h('div');
    body.replaceChildren(headEl, tableBox);
    function renderTable() {
      const q = filter.toLowerCase();
      const rows = all.filter((c) => (showRevoked || !c.revoked) && (!q || c.name.toLowerCase().includes(q)));
      if (!all.length) {
        tableBox.replaceChildren(empty('clients', 'No client certificates yet',
          pki.available ? 'Create a client to get a ready-to-use .ovpn profile for the stock OpenVPN client.' : pki.reason,
          pki.available && pki.writable ? h('button', { type: 'button', class: 'btn primary', onclick: () => newClient() }, icon('plus'), 'New client') : null));
        return;
      }
      if (!rows.length) { tableBox.replaceChildren(empty('search', 'No matching clients')); return; }
      tableBox.replaceChildren(h('div', { class: 'table-wrap' }, h('table', { class: 'data stackable' },
        h('thead', null, h('tr', null, ['Name', 'Status', 'Expires', 'Serial', ''].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', null, rows.map(row)))));
    }
    renderTable();
    if (hadFocus) search.focus();
  }

  function status(c) {
    if (c.revoked) return h('span', { class: 'badge danger' }, 'Revoked ' + dateStr(c.revokedAt));
    if (c.expired) return h('span', { class: 'badge warn' }, 'Expired');
    if (c.disabled) return h('span', { class: 'badge warn' }, 'Disabled');
    if (c.online) return h('span', { class: 'badge ok' }, c.online > 1 ? `Online (${c.online})` : 'Online');
    return h('span', { class: 'badge' }, 'Offline');
  }

  function row(c) {
    const pki = data.pki;
    return h('tr', null,
      h('td', { class: 'primary-cell' }, h('div', { class: 'cell-main' }, c.name),
        h('div', { class: 'cell-sub' }, [c.ccd ? 'custom settings' : null, c.user ? 'has a password user' : null].filter(Boolean).join(' · ') || null)),
      h('td', { 'data-label': 'Status' }, status(c)),
      h('td', { 'data-label': 'Expires', class: 'nowrap' }, dateStr(c.notAfter)),
      h('td', { 'data-label': 'Serial' }, h('span', { class: 'mono small muted', title: c.serial }, c.serial.slice(0, 12) + '…')),
      h('td', { class: 'actions-cell' }, c.revoked ? null : h('div', { class: 'row-actions' },
        h('button', { type: 'button', class: 'btn sm', onclick: () => profileDialog(c.name) }, icon('download'), 'Profile'),
        h('button', { type: 'button', class: 'btn sm', onclick: () => ccdDialog(c), disabled: !data.ccd.configured, title: data.ccd.configured ? 'Static address, routes and options for this client' : 'Set client-config-dir in the configuration to use per-client settings' }, icon('sliders'), 'Settings'),
        h('button', { type: 'button', class: 'btn sm ghost danger-text', onclick: () => revoke(c), disabled: !pki.writable, title: pki.writable ? 'Revoke this certificate' : pki.reason }, icon('ban'), 'Revoke'))));
  }

  // ---- new client ----

  async function newClient() {
    const name = h('input', { type: 'text', required: true, autofocus: true, autocomplete: 'off', spellcheck: 'false', pattern: '[A-Za-z0-9][A-Za-z0-9._@-]{0,63}', placeholder: 'e.g. alice-laptop' });
    const days = h('input', { type: 'number', min: '1', max: '36500', value: '3650' });
    const usersOn = !!(app.status && app.status.auth.usersFile);
    const withUser = checkbox('Also create a password user with this name', false, 'For servers that ask clients for a username and password.');
    const pw = h('input', { type: 'text', autocomplete: 'new-password', spellcheck: 'false' });
    const pwRow = h('div', { class: 'field', hidden: true }, h('label', { for: 'nc-pw' }, 'Password'),
      h('div', { class: 'input-row' }, pw, h('button', { type: 'button', class: 'btn', onclick: () => { pw.value = randomPassword(); } }, icon('wand'), 'Generate')));
    pw.id = 'nc-pw';
    withUser.input.addEventListener('change', () => { pwRow.hidden = !withUser.input.checked; if (withUser.input.checked && !pw.value) pw.value = randomPassword(); });
    const err = h('div', { class: 'form-error', role: 'alert', hidden: true }, icon('alert'), h('span'));
    const create = h('button', { type: 'submit', class: 'btn primary' }, 'Create client');
    const created = await openDialog((close) => ({
      title: 'New client', icon: 'plus',
      body: [
        h('p', null, 'Issues a client certificate signed by the server\'s CA. You can download its profile next.'),
        h('div', { class: 'fields one' },
          field('Name', name, 'Letters, digits, ".", "_", "@" and "-". This is the certificate\'s common name.'),
          field('Valid for (days)', days)),
        usersOn ? withUser.el : null, usersOn ? pwRow : null, err,
      ],
      onSubmit: () => busy(create, async () => {
        err.hidden = true;
        try {
          const body = { name: name.value.trim(), days: Number(days.value) || 3650 };
          if (withUser.input.checked) body.password = pw.value;
          await api('POST', '/clients', body);
          close({ name: body.name, password: body.password });
        } catch (e) {
          err.hidden = false; err.lastChild.textContent = e.message;
        }
      }),
      actions: [h('button', { type: 'button', class: 'btn', onclick: () => close(null) }, 'Cancel'), create],
    }));
    if (!created) return;
    toast('ok', `Client ${created.name} created`);
    await load();
    profileDialog(created.name, created.password);
  }

  // ---- profile download ----

  async function profileDialog(name, password) {
    const d = data.defaults || { remote: location.hostname, port: 1194, proto: 'udp', protos: ['udp'] };
    const remote = h('input', { type: 'text', value: d.remote, required: true, spellcheck: 'false' });
    const port = h('input', { type: 'number', value: String(d.port), min: '1', max: '65535' });
    const proto = select(d.protos.length ? d.protos : ['udp', 'tcp'], d.proto);
    const err = h('div', { class: 'form-error', role: 'alert', hidden: true }, icon('alert'), h('span'));
    const dl = h('button', { type: 'submit', class: 'btn primary' }, icon('download'), 'Download ' + name + '.ovpn');
    const notes = [
      d.wrap ? `${d.wrap} key included` : null,
      d.authUserPass ? 'asks for a username and password' : null,
      d.noCert ? 'no client certificate (verify-client-cert none)' : null,
      d.tap ? 'dev tap' : null,
    ].filter(Boolean);
    await openDialog((close) => ({
      title: 'Download profile', icon: 'download',
      body: [
        h('p', null, 'A ready-to-use profile for the stock OpenVPN client (2.5 or newer), with the certificates and keys inlined. Treat it like a password.'),
        password ? h('div', null, h('div', { class: 'label' }, 'Password for user ' + name),
          h('div', { class: 'secret' }, h('span', null, password), h('button', { type: 'button', class: 'btn sm', onclick: () => copyText(password) }, icon('copy'), 'Copy')),
          h('p', { class: 'hint small muted' }, 'Shown only now. Give it to the user together with the profile.')) : null,
        h('div', { class: 'fields' },
          field('Server address', remote, 'The host name or IP clients connect to.', { wide: true }),
          field('Port', port), field('Protocol', proto)),
        notes.length ? h('p', { class: 'small muted' }, 'This profile: ' + notes.join(', ') + '.') : null,
        err,
      ],
      onSubmit: () => busy(dl, async () => {
        err.hidden = true;
        try {
          const q = new URLSearchParams({ remote: remote.value.trim(), port: port.value, proto: proto.value });
          await download(`/clients/${encodeURIComponent(name)}/profile?${q}`, name + '.ovpn');
          toast('ok', 'Profile downloaded', name + '.ovpn');
          close(true);
        } catch (e) { err.hidden = false; err.lastChild.textContent = e.message; }
      }),
      actions: [h('button', { type: 'button', class: 'btn', onclick: () => close(false) }, 'Close'), dl],
    }));
  }

  // ---- revoke ----

  async function revoke(c) {
    const ok = await confirmDialog({
      title: `Revoke ${c.name}?`, confirm: 'Revoke certificate',
      message: h('div', null,
        h('p', null, 'The certificate is added to the revocation list and can never be used again. This cannot be undone; you can issue a new certificate with the same name afterwards.'),
        c.online ? h('p', null, h('strong', null, `${c.name} is connected now.`), data.crl.configured ? ' It is disconnected within seconds.' : ' Without crl-verify it stays connected and can reconnect.') : null),
    });
    if (!ok) return;
    try {
      const r = await api('POST', `/clients/${encodeURIComponent(c.name)}/revoke`, {});
      if (r.warning) toast('warn', `${c.name} revoked, but not enforced`, r.warning);
      else toast('ok', `${c.name} revoked`, r.online ? 'Its session is being disconnected.' : null);
      await load();
    } catch (e) {
      toast('error', 'Could not revoke', e.message);
    }
  }

  // ---- per-client settings (client-config-dir) ----

  async function ccdDialog(c) {
    let cur;
    try {
      cur = await api('GET', `/ccd/${encodeURIComponent(c.name)}`);
    } catch (e) { toast('error', 'Could not load the client settings', e.message); return; }
    const s = cur.settings;
    const ip = h('input', { type: 'text', value: s.ip, placeholder: 'automatic', spellcheck: 'false' });
    const ip6 = h('input', { type: 'text', value: s.ip6, placeholder: cur.subnet6 ? 'automatic' : 'needs server-ipv6', disabled: !cur.subnet6 && !s.ip6, spellcheck: 'false' });
    const iroutes = h('textarea', { rows: '3', spellcheck: 'false', placeholder: '192.168.10.0/24\nfd00:10::/64' });
    iroutes.value = s.iroutes.join('\n');
    const push = h('textarea', { rows: '3', spellcheck: 'false', placeholder: 'route 10.20.0.0 255.255.0.0\ndhcp-option DNS 10.8.0.1' });
    push.value = s.push.join('\n');
    const pushReset = checkbox('Don\'t push the server\'s options (push-reset)', s.pushReset, 'Only the options above are pushed to this client.');
    const disabled = checkbox('Disable this client', s.disabled, 'The server refuses it until this is unchecked (disable).');
    const raw = h('textarea', { rows: '12', spellcheck: 'false' });
    raw.value = cur.text;
    const err = h('div');
    const ro = !cur.writable;
    for (const el of [ip, ip6, iroutes, push, pushReset.input, disabled.input, raw]) if (ro) el.disabled = true;
    let tab = 'settings';
    const panel = h('div');
    const tabs = h('div', { class: 'tabs', role: 'tablist' });
    const settingsPanel = h('div', { class: 'stack' },
      h('div', { class: 'fields' },
        field('Static IPv4 address', ip, `ifconfig-push, in ${cur.subnet}`),
        field('Static IPv6 address', ip6, cur.subnet6 ? `ifconfig-ipv6-push ADDR/BITS, in ${cur.subnet6}` : 'The server has no IPv6 subnet.')),
      field('Networks behind this client (iroute)', iroutes, 'One prefix per line. Also add them as routes in the configuration, and enable client-to-client.'),
      field('Extra options pushed to this client', push, 'One option per line, without "push" and quotes.'),
      pushReset.el, disabled.el);
    const rawPanel = h('div', null, field('File ' + cur.path, raw, 'The client-config-dir file as it is on disk.'));
    const setTab = (t) => {
      tab = t;
      tabs.querySelectorAll('button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === t)));
      panel.replaceChildren(t === 'settings' ? settingsPanel : rawPanel);
    };
    for (const [t, label] of [['settings', 'Settings'], ['raw', 'File']]) {
      tabs.append(h('button', { type: 'button', role: 'tab', dataset: { tab: t }, onclick: () => setTab(t) }, label));
    }
    setTab('settings');
    const save = h('button', { type: 'submit', class: 'btn primary', disabled: ro }, 'Save');
    const lines = (t) => t.value.split('\n').map((x) => x.trim()).filter(Boolean);
    const saved = await openDialog((close) => ({
      title: 'Settings for ' + c.name, icon: 'sliders', wide: true,
      body: [
        ro ? banner('info', 'Read-only', cur.reason) : null,
        h('p', null, 'Changes take effect the next time the client connects.'),
        tabs, panel, err,
      ],
      onSubmit: () => busy(save, async () => {
        err.replaceChildren();
        const body = tab === 'raw' ? { text: raw.value } : {
          settings: { ip: ip.value.trim(), ip6: ip6.value.trim(), iroutes: lines(iroutes), push: lines(push), pushReset: pushReset.input.checked, disabled: disabled.input.checked },
        };
        try {
          const r = await api('PUT', `/ccd/${encodeURIComponent(c.name)}`, body);
          close(r);
        } catch (e) {
          const errs = (e instanceof APIError && e.body.errors) || [];
          err.append(banner('danger', e.message, errs.map((x) => (x.line ? `line ${x.line}: ` : '') + x.message).join('; ')));
        }
      }),
      actions: [
        cur.exists && !ro ? h('button', {
          type: 'button', class: 'btn ghost danger-text', onclick: async () => {
            if (!await confirmDialog({ title: 'Delete the settings file?', message: `${cur.path} is deleted; ${c.name} gets the server's defaults at its next connection.`, confirm: 'Delete' })) return;
            try { await api('DELETE', `/ccd/${encodeURIComponent(c.name)}`); close({ deleted: true }); } catch (e) { toast('error', 'Could not delete', e.message); }
          },
        }, icon('trash'), 'Delete file') : null,
        h('button', { type: 'button', class: 'btn', onclick: () => close(null) }, 'Cancel'), save,
      ],
    }));
    if (!saved) return;
    await load();
    const online = data.clients.find((x) => x.name === c.name && x.online);
    const sess = app.live && app.live.sessions.find((x) => x.commonName === c.name);
    if (online && sess) {
      toast('ok', saved.deleted ? 'Settings deleted' : 'Settings saved', `${c.name} is connected: reconnect it from the dashboard to apply them now.`);
    } else {
      toast('ok', saved.deleted ? 'Settings deleted' : 'Settings saved', 'They apply at the client\'s next connection.');
    }
  }

  await load();
  const onEvent = (kind) => { if (kind === 'status' && data) render(); };
  app.listeners.add(onEvent);
  // Online status follows the live session list.
  const timer = setInterval(() => { if (!document.querySelector('dialog[open]')) load(); }, 15000);
  return () => { app.listeners.delete(onEvent); clearInterval(timer); };
}
