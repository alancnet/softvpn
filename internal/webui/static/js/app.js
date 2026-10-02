// softvpn web UI: login, layout, routing (#/page) and the live event stream.
import { h, icon, api, setCSRF, setUnauthorizedHandler, toast, openDialog, field, busy, APIError } from './lib.js';
import { dashboardPage } from './pages/dashboard.js';
import { clientsPage } from './pages/clients.js';
import { usersPage } from './pages/users.js';
import { configPage } from './pages/config.js';
import { logsPage } from './pages/logs.js';

const pages = {
  dashboard: { title: 'Dashboard', icon: 'dashboard', render: dashboardPage },
  clients: { title: 'Clients', icon: 'clients', render: clientsPage },
  users: { title: 'Password users', short: 'Users', icon: 'users', render: usersPage },
  config: { title: 'Configuration', icon: 'config', render: configPage },
  logs: { title: 'Logs', icon: 'logs', render: logsPage },
};

// The shared state pages read: session, status, and the live stream.
export const app = {
  user: '',
  canChangePassword: false,
  status: null,
  live: null, // latest "sessions" event
  listeners: new Set(), // fn(event, data)
  guard: null, // fn() -> message if leaving the page loses edits
  refreshStatus,
  navigate: (page) => { location.hash = '#/' + page; },
};

const root = document.getElementById('app');

// ---- theme ----

const themes = ['auto', 'light', 'dark'];
function getTheme() {
  try { return localStorage.getItem('softvpn-theme') || 'auto'; } catch { return 'auto'; }
}
function applyTheme(t) {
  if (t === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
}
function themeButton() {
  const label = { auto: 'Theme: automatic', light: 'Theme: light', dark: 'Theme: dark' };
  const ic = { auto: 'auto', light: 'sun', dark: 'moon' };
  const btn = h('button', { type: 'button', class: 'btn ghost sm icon-only' });
  const paint = () => {
    const t = getTheme();
    btn.replaceChildren(icon(ic[t]));
    btn.title = label[t] + ' (click to change)';
    btn.setAttribute('aria-label', btn.title);
  };
  btn.addEventListener('click', () => {
    const t = themes[(themes.indexOf(getTheme()) + 1) % themes.length];
    try { localStorage.setItem('softvpn-theme', t); } catch { /* private mode */ }
    applyTheme(t);
    document.querySelectorAll('.theme-btn-sync').forEach((b) => b.dispatchEvent(new Event('repaint')));
  });
  btn.classList.add('theme-btn-sync');
  btn.addEventListener('repaint', paint);
  paint();
  return btn;
}
applyTheme(getTheme());

// ---- live updates (Server-Sent Events) ----

let es = null;
function connectEvents() {
  if (es) es.close();
  es = new EventSource('/api/events?logs=1&since=' + (app.logSince || 0));
  es.addEventListener('sessions', (e) => {
    const data = JSON.parse(e.data);
    const prevStart = app.live && app.live.engineStarted;
    app.live = data;
    if (prevStart && data.engineStarted && prevStart !== data.engineStarted) refreshStatus();
    updateNavCounts();
    app.listeners.forEach((fn) => fn('sessions', data));
  });
  es.addEventListener('log', (e) => {
    const entries = JSON.parse(e.data);
    if (entries.length) app.logSince = entries[entries.length - 1].seq;
    app.logs = (app.logs || []).concat(entries).slice(-2000);
    app.listeners.forEach((fn) => fn('log', entries));
  });
  es.onerror = () => {
    // EventSource reconnects by itself; a 401 means the session ended.
    if (es && es.readyState === EventSource.CLOSED) {
      setTimeout(async () => { if (await checkSession()) connectEvents(); else sessionEnded(); }, 3000);
    }
  };
}

async function refreshStatus() {
  try {
    app.status = await api('GET', '/status');
    app.listeners.forEach((fn) => fn('status', app.status));
  } catch (e) {
    if (!(e instanceof APIError && e.status === 401)) toast('error', 'Could not load the server status', e.message);
  }
  return app.status;
}

function updateNavCounts() {
  const n = app.live ? app.live.sessions.length : 0;
  document.querySelectorAll('.nav-count-dashboard').forEach((el) => { el.textContent = String(n); el.hidden = n === 0; });
}

// ---- login ----

function loginView(message) {
  if (es) { es.close(); es = null; }
  const user = h('input', { type: 'text', name: 'username', autocomplete: 'username', required: true, value: 'admin', autocapitalize: 'none', spellcheck: 'false' });
  const pass = h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true, autofocus: true });
  const err = h('div', { class: 'form-error', role: 'alert', hidden: !message }, icon('alert'), h('span', null, message || ''));
  const submit = h('button', { type: 'submit', class: 'btn primary' }, 'Log in');
  const form = h('form', { novalidate: true },
    field('Username', user), field('Password', pass), err, submit);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!user.value || !pass.value) {
      err.hidden = false;
      err.lastChild.textContent = 'Enter your username and password.';
      return;
    }
    await busy(submit, async () => {
      try {
        const r = await api('POST', '/login', { username: user.value, password: pass.value }, { login: true });
        setCSRF(r.csrf);
        app.user = r.user;
        await checkSession();
        await start();
      } catch (ex) {
        err.hidden = false;
        err.lastChild.textContent = ex.message;
        pass.select();
      }
    });
  });
  root.className = '';
  root.removeAttribute('aria-busy');
  root.replaceChildren(h('main', { class: 'login-wrap' },
    h('div', { class: 'login' },
      h('div', { class: 'card' }, h('div', { class: 'card-body' },
        h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, icon('shield')), 'softvpn'),
        h('h1', null, 'Administrator login'),
        h('p', { class: 'lead' }, 'Manage your VPN server, clients and configuration.'),
        form)),
      h('p', { class: 'login-foot' }, 'The first password is in the server log (or set ', h('code', null, 'SOFTVPN_WEB_PASSWORD'), ').'),
      h('div', { class: 'login-foot' }, themeButton()))));
  (pass.value ? submit : pass).focus();
}

// ---- layout ----

let current = null; // {name, cleanup}

function navLinks() {
  return h('nav', { class: 'nav', 'aria-label': 'Main' }, Object.entries(pages).map(([name, p]) =>
    h('a', { href: '#/' + name, dataset: { page: name } }, icon(p.icon), p.short || p.title,
      name === 'dashboard' ? h('span', { class: 'count nav-count-dashboard', hidden: true, title: 'connected clients' }, '0') : null)));
}

function shell() {
  const logout = async () => {
    try { await api('POST', '/logout', {}); } catch { /* ended anyway */ }
    setCSRF('');
    loginView('You have logged out.');
  };
  const account = () => accountDialog();
  const who = h('div', { class: 'who' }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, (app.user[0] || '?').toUpperCase()), h('span', null, app.user));
  const sidebar = h('aside', { class: 'sidebar' },
    h('a', { class: 'brand', href: '#/dashboard' }, h('span', { class: 'brand-mark' }, icon('shield')),
      h('span', null, 'softvpn', h('small', null, 'Server admin'))),
    navLinks(),
    h('div', { class: 'sidebar-foot' }, h('div', { class: 'split' }, who, themeButton()),
      h('div', { class: 'foot-actions' },
        h('button', { type: 'button', class: 'btn sm', onclick: account, title: 'Account' }, icon('key'), 'Account'),
        h('button', { type: 'button', class: 'btn sm', onclick: logout, title: 'Log out' }, icon('logout'), 'Log out'))));
  const topbar = h('header', { class: 'topbar' },
    h('div', { class: 'topbar-row' },
      h('a', { class: 'brand', href: '#/dashboard' }, h('span', { class: 'brand-mark' }, icon('shield')), 'softvpn'),
      h('div', { class: 'foot-actions' }, themeButton(),
        h('button', { type: 'button', class: 'btn ghost sm icon-only', onclick: account, 'aria-label': 'Account', title: 'Account' }, icon('key')),
        h('button', { type: 'button', class: 'btn ghost sm icon-only', onclick: logout, 'aria-label': 'Log out', title: 'Log out' }, icon('logout')))),
    navLinks());
  const main = h('main', { class: 'main', id: 'main', tabindex: '-1' });
  root.className = '';
  root.removeAttribute('aria-busy');
  root.replaceChildren(h('div', { class: 'shell' }, sidebar, h('div', null, topbar, main)));
  return main;
}

function accountDialog() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true, autofocus: true });
  const nw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: '8' });
  const nw2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const err = h('div', { class: 'form-error', role: 'alert', hidden: true }, icon('alert'), h('span'));
  const save = h('button', { type: 'submit', class: 'btn primary', disabled: !app.canChangePassword }, 'Change password');
  return openDialog((close) => ({
    title: 'Account: ' + app.user, icon: 'key',
    body: app.canChangePassword ? [
      h('p', null, 'Change the password you log in to the web UI with. Other sessions of this account are logged out.'),
      h('div', { class: 'fields one' }, field('Current password', cur), field('New password', nw, 'At least 8 characters.'), field('Repeat the new password', nw2)),
      err,
    ] : [h('p', null, 'This account cannot be changed here: the administrators file is not writable, or the password comes from SOFTVPN_WEB_PASSWORD.')],
    onSubmit: () => busy(save, async () => {
      err.hidden = true;
      if (nw.value !== nw2.value) { err.hidden = false; err.lastChild.textContent = 'The new passwords do not match.'; return; }
      try {
        await api('POST', '/session/password', { current: cur.value, new: nw.value });
        toast('ok', 'Password changed');
        close(true);
      } catch (e) { err.hidden = false; err.lastChild.textContent = e.message; }
    }),
    actions: [h('button', { type: 'button', class: 'btn', onclick: () => close(false) }, 'Close'), app.canChangePassword ? save : null],
  }));
}

let mainEl = null;

async function route() {
  if (!mainEl) return;
  const name = (location.hash.match(/^#\/(\w+)/) || [])[1] || 'dashboard';
  const page = pages[name] ? name : 'dashboard';
  if (current && current.name === page && current.hash === location.hash) return;
  if (current && app.guard) {
    const msg = app.guard();
    if (msg && !confirm(msg)) {
      history.replaceState(null, '', current.hash);
      return;
    }
  }
  app.guard = null;
  if (current && current.cleanup) current.cleanup();
  document.querySelectorAll('.nav a').forEach((a) => {
    if (a.dataset.page === page) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  document.title = pages[page].title + ' · softvpn';
  mainEl.replaceChildren();
  current = { name: page, hash: location.hash || '#/dashboard' };
  try {
    current.cleanup = await pages[page].render(mainEl, app);
  } catch (e) {
    mainEl.replaceChildren(h('div', { class: 'banner danger' }, icon('alert'), h('div', null, h('strong', null, 'This page failed to load'), h('p', null, e.message))));
  }
  if (document.activeElement === document.body) mainEl.focus({ preventScroll: true });
}

async function start() {
  await refreshStatus();
  mainEl = shell();
  current = null;
  connectEvents();
  if (!location.hash) history.replaceState(null, '', '#/dashboard');
  await route();
}

async function checkSession() {
  try {
    const s = await api('GET', '/session');
    if (!s.loggedIn) return false;
    setCSRF(s.csrf);
    app.user = s.user;
    app.canChangePassword = s.canChangePassword;
    return true;
  } catch {
    return false;
  }
}

window.addEventListener('hashchange', route);
window.addEventListener('beforeunload', (e) => {
  if (app.guard && app.guard()) { e.preventDefault(); e.returnValue = ''; }
});
setUnauthorizedHandler(sessionEnded);
function sessionEnded() {
  if (!mainEl) return; // already at the login page
  if (current && current.cleanup) current.cleanup();
  app.guard = null;
  mainEl = null;
  current = null;
  loginView('Your session has ended. Please log in again.');
}

(async () => {
  if (await checkSession()) await start();
  else loginView();
})();
