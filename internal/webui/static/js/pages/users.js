// Password users: the server's auth-user-pass-file.
import { h, icon, api, toast, openDialog, confirmDialog, field, banner, empty, loading, busy, download, randomPassword, copyText, select } from '../lib.js';
import { changeSettings } from '../apply.js';

export async function usersPage(main, app) {
  const head = h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Password users'), h('p', null, 'Usernames and passwords the server accepts (auth-user-pass-file).')));
  const addBtn = h('button', { type: 'button', class: 'btn primary', onclick: () => addUser() }, icon('plus'), 'Add user');
  head.append(h('div', { class: 'page-actions' }, addBtn));
  const banners = h('div');
  const body = h('section', { class: 'card' }, loading());
  main.append(head, banners, body);
  let data = null;

  async function load() {
    try {
      data = await api('GET', '/users');
      render();
    } catch (e) {
      body.replaceChildren(h('div', { class: 'card-body' }, banner('danger', 'Could not load the users', e.message)));
    }
  }

  function render() {
    banners.replaceChildren();
    addBtn.hidden = !data.configured;
    addBtn.disabled = !!data.readOnly;
    if (!data.configured) {
      const writable = app.status && app.status.config.writable;
      const dir = app.status && app.status.config.file ? app.status.config.file.replace(/[^/]*$/, '') : '';
      body.replaceChildren(empty('users', 'Password authentication is off',
        'Add an auth-user-pass-file to the configuration to let clients log in with a username and password, with or without a certificate.',
        writable ? h('button', {
          type: 'button', class: 'btn primary', onclick: () => enable(dir),
        }, icon('lock'), 'Turn on password authentication') : h('p', { class: 'small' }, app.status ? app.status.config.reason : '')));
      return;
    }
    if (data.readOnly) banners.append(banner('info', 'Read-only', data.readOnly));
    const s = app.status && app.status.auth;
    if (s) {
      const mode = { require: 'Clients need a certificate and a password.', optional: s.authUserPassOptional ? 'Clients need a certificate or a password.' : 'Clients need a password; a certificate is optional.', none: 'Clients log in with a password only, no certificate.' }[s.verifyClientCert];
      if (mode) banners.append(banner('info', 'How clients log in', mode + (s.usernameAsCommonName ? ' Sessions are named after the user.' : '')));
    }
    if (!data.users.length) {
      body.replaceChildren(empty('users', 'No users yet', 'Users you add here can log in right away; no restart needed.',
        h('button', { type: 'button', class: 'btn primary', onclick: () => addUser() }, icon('plus'), 'Add user')));
      return;
    }
    const canProfile = data.defaults && data.defaults.passwordOnly;
    body.replaceChildren(
      h('div', { class: 'card-head' }, h('div', null, h('h2', null, 'Users'), h('p', null, data.file))),
      h('div', { class: 'table-wrap' }, h('table', { class: 'data stackable' },
        h('thead', null, h('tr', null, ['Name', 'Status', ''].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', null, data.users.map((u) => h('tr', null,
          h('td', { class: 'primary-cell' }, h('div', { class: 'cell-main' }, u.name)),
          h('td', { 'data-label': 'Status' }, u.online ? h('span', { class: 'badge ok' }, 'Online') : h('span', { class: 'badge' }, 'Offline')),
          h('td', { class: 'actions-cell' }, h('div', { class: 'row-actions' },
            canProfile ? h('button', { type: 'button', class: 'btn sm', onclick: () => profile(u.name), title: 'A profile without a certificate that asks for this user\'s password' }, icon('download'), 'Profile') : null,
            h('button', { type: 'button', class: 'btn sm', onclick: () => setPassword(u.name), disabled: !!data.readOnly }, icon('key'), 'Password'),
            h('button', { type: 'button', class: 'btn sm ghost danger-text', onclick: () => del(u), disabled: !!data.readOnly }, icon('trash'), 'Delete')))))))));
  }

  async function enable(dir) {
    const file = h('input', { type: 'text', value: dir + 'users', spellcheck: 'false' });
    const mode = select([['optional', 'Certificate or password (verify-client-cert optional)'], ['none', 'Password only, no certificates (verify-client-cert none)'], ['require', 'Certificate and password (require)']], 'optional');
    const ok = await openDialog((close) => ({
      title: 'Turn on password authentication', icon: 'lock',
      body: [h('div', { class: 'fields one' }, field('Users file', file, 'Created empty if it does not exist.'), field('Clients log in with', mode))],
      onSubmit: () => close(true),
      actions: [h('button', { type: 'button', class: 'btn', onclick: () => close(false) }, 'Cancel'), h('button', { type: 'submit', class: 'btn primary' }, 'Continue')],
    }));
    if (!ok) return;
    const r = await changeSettings(app, (s) => {
      s.authUserPassFile = file.value.trim();
      s.verifyClientCert = mode.value === 'require' ? '' : mode.value;
      s.authUserPassOptional = mode.value === 'optional';
      s.usernameAsCommonName = true;
    }, { title: 'Turn on password authentication' });
    if (r && r.ok) load();
  }

  async function addUser() {
    const name = h('input', { type: 'text', required: true, autofocus: true, autocomplete: 'off', spellcheck: 'false' });
    const pw = h('input', { id: 'au-pw', type: 'text', required: true, autocomplete: 'new-password', spellcheck: 'false', value: randomPassword() });
    const err = h('div', { class: 'form-error', role: 'alert', hidden: true }, icon('alert'), h('span'));
    const save = h('button', { type: 'submit', class: 'btn primary' }, 'Add user');
    const res = await openDialog((close) => ({
      title: 'Add user', icon: 'plus',
      body: [h('div', { class: 'fields one' }, field('Username', name),
        h('div', { class: 'field' }, h('label', { for: 'au-pw' }, 'Password'), h('div', { class: 'input-row' }, pw,
          h('button', { type: 'button', class: 'btn', onclick: () => { pw.value = randomPassword(); } }, icon('wand'), 'Generate')))), err],
      onSubmit: () => busy(save, async () => {
        err.hidden = true;
        try {
          await api('POST', '/users', { name: name.value.trim(), password: pw.value });
          close({ name: name.value.trim(), password: pw.value });
        } catch (e) { err.hidden = false; err.lastChild.textContent = e.message; }
      }),
      actions: [h('button', { type: 'button', class: 'btn', onclick: () => close(null) }, 'Cancel'), save],
    }));
    if (!res) return;
    await load();
    showSecret(`User ${res.name} added`, res.name, res.password);
  }

  function showSecret(title, name, password) {
    const canProfile = data.defaults && data.defaults.passwordOnly;
    openDialog((close) => ({
      title, icon: 'checkCircle',
      body: [h('p', null, 'The password is shown only now. The user can log in right away.'),
        h('div', { class: 'secret' }, h('span', null, password), h('button', { type: 'button', class: 'btn sm', onclick: () => copyText(password) }, icon('copy'), 'Copy'))],
      actions: [canProfile ? h('button', { type: 'button', class: 'btn', onclick: () => profile(name) }, icon('download'), 'Download profile') : null,
        h('button', { type: 'button', class: 'btn primary', onclick: () => close() }, 'Done')],
    }));
  }

  async function setPassword(name) {
    const pw = h('input', { id: 'sp-pw', type: 'text', required: true, autofocus: true, autocomplete: 'new-password', spellcheck: 'false', value: randomPassword() });
    const err = h('div', { class: 'form-error', role: 'alert', hidden: true }, icon('alert'), h('span'));
    const save = h('button', { type: 'submit', class: 'btn primary' }, 'Change password');
    const res = await openDialog((close) => ({
      title: 'New password for ' + name, icon: 'key',
      body: [h('p', null, 'Connected sessions keep running; the new password is needed at the next login or renegotiation.'),
        h('div', { class: 'field' }, h('label', { for: 'sp-pw' }, 'New password'), h('div', { class: 'input-row' }, pw,
          h('button', { type: 'button', class: 'btn', onclick: () => { pw.value = randomPassword(); } }, icon('wand'), 'Generate'))), err],
      onSubmit: () => busy(save, async () => {
        try {
          await api('PUT', `/users/${encodeURIComponent(name)}`, { password: pw.value });
          close(pw.value);
        } catch (e) { err.hidden = false; err.lastChild.textContent = e.message; }
      }),
      actions: [h('button', { type: 'button', class: 'btn', onclick: () => close(null) }, 'Cancel'), save],
    }));
    if (res) showSecret('Password changed', name, res);
  }

  async function del(u) {
    const ok = await confirmDialog({
      title: `Delete user ${u.name}?`, confirm: 'Delete user',
      message: u.online ? `${u.name} is connected and is disconnected within seconds. They can no longer log in.` : `${u.name} can no longer log in.`,
    });
    if (!ok) return;
    try {
      await api('DELETE', `/users/${encodeURIComponent(u.name)}`);
      toast('ok', `User ${u.name} deleted`);
      load();
    } catch (e) { toast('error', 'Could not delete the user', e.message); }
  }

  async function profile(name) {
    try {
      await download(`/users/${encodeURIComponent(name)}/profile`, name + '.ovpn');
      toast('ok', 'Profile downloaded', `${name}.ovpn asks for ${name}'s password when it connects.`);
    } catch (e) { toast('error', 'Could not make the profile', e.message); }
  }

  await load();
  const timer = setInterval(() => { if (!document.querySelector('dialog[open]')) load(); }, 15000);
  return () => clearInterval(timer);
}
