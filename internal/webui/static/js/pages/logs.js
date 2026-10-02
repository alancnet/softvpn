// Logs: the server's recent log lines, with a live tail.
import { h, icon, api, select, toast } from '../lib.js';

const LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

export async function logsPage(main, app) {
  const level = select([['DEBUG', 'All levels'], ['INFO', 'Info and above'], ['WARN', 'Warnings and errors'], ['ERROR', 'Errors only']], 'DEBUG', { 'aria-label': 'Minimum level' });
  const search = h('input', { type: 'search', placeholder: 'Filter (e.g. a client name)', 'aria-label': 'Filter log lines' });
  let paused = false;
  const pauseBtn = h('button', { type: 'button', class: 'btn', 'aria-pressed': 'false' });
  const paintPause = () => {
    pauseBtn.replaceChildren(icon(paused ? 'play' : 'pause'), paused ? 'Resume' : 'Pause');
    pauseBtn.setAttribute('aria-pressed', String(paused));
  };
  paintPause();
  const box = h('div', { class: 'logbox', role: 'log', 'aria-live': 'off', tabindex: '0', 'aria-label': 'Server log' });
  const count = h('span', { class: 'muted small' });
  const head = h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Logs'), h('p', null, 'The most recent server log lines (kept in memory, up to 2000).')),
    h('div', { class: 'page-actions' }, h('button', { type: 'button', class: 'btn', onclick: save }, icon('download'), 'Download')));
  main.append(head,
    h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search'), search), level, pauseBtn, count),
    box);

  let entries = (app.logs || []).slice();
  if (!entries.length) {
    try { entries = (await api('GET', '/logs')).entries; app.logs = entries.slice(); } catch (e) { toast('error', 'Could not load the logs', e.message); }
  }
  let pending = [];

  const matches = (e) => LEVELS[e.level] >= LEVELS[level.value] &&
    (!search.value || (e.msg + ' ' + e.attrs).toLowerCase().includes(search.value.toLowerCase()));
  const line = (e) => h('div', { class: 'logline' },
    h('span', { class: 't' }, new Date(e.time).toLocaleTimeString(undefined, { hour12: false })),
    h('span', { class: 'lv ' + e.level }, e.level),
    h('span', { class: 'm' }, e.msg, e.attrs ? h('span', { class: 'a' }, ' ' + e.attrs) : null));
  const atBottom = () => box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  const paint = () => {
    const shown = entries.filter(matches);
    box.replaceChildren(...shown.map(line));
    count.textContent = `${shown.length} of ${entries.length} lines`;
    box.scrollTop = box.scrollHeight;
  };
  const add = (list) => {
    entries = entries.concat(list).slice(-2000);
    const stick = atBottom();
    const shown = list.filter(matches);
    box.append(...shown.map(line));
    while (box.childElementCount > 2000) box.firstChild.remove();
    count.textContent = `${box.childElementCount} of ${entries.length} lines`;
    if (stick) box.scrollTop = box.scrollHeight;
  };
  function save() {
    const text = entries.map((e) => `${e.time} ${e.level} ${e.msg} ${e.attrs}`.trimEnd()).join('\n') + '\n';
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: 'softvpn.log' });
    document.body.append(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  level.addEventListener('change', paint);
  search.addEventListener('input', paint);
  pauseBtn.addEventListener('click', () => {
    paused = !paused;
    paintPause();
    if (!paused && pending.length) { add(pending); pending = []; }
  });
  paint();
  const onEvent = (kind, data) => {
    if (kind !== 'log') return;
    if (paused) pending = pending.concat(data).slice(-2000);
    else add(data);
  };
  app.listeners.add(onEvent);
  return () => app.listeners.delete(onEvent);
}
