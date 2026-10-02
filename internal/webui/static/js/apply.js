// Reviewing and applying a new server.conf: a diff, a warning that the
// server restarts (clients reconnect), and the save/apply progress.
import { h, icon, api, toast, openDialog, diffView, APIError } from './lib.js';

// reviewAndApply shows the change from oldText to newText and, once
// confirmed, saves and applies it. Resolves {ok, hash} or {ok: false,
// errors} (validation errors, nothing saved) or undefined if cancelled.
export async function reviewAndApply(app, oldText, newText, hash, opts = {}) {
  const { el: diff, adds, dels } = diffView(oldText, newText);
  const clients = app.live ? app.live.sessions.length : 0;
  const steps = h('div', { class: 'steps', hidden: true });
  const step = (text) => {
    const s = h('div', { class: 'step' }, h('span', { class: 'dot' }), h('span', null, text));
    steps.append(s);
    return s;
  };
  const errBox = h('div');
  let running = false;
  return openDialog((close) => {
    const cancel = h('button', { type: 'button', class: 'btn', onclick: () => close(undefined) }, 'Cancel');
    const go = h('button', { type: 'submit', class: 'btn primary' }, icon('refresh'), 'Save and restart');
    const apply = async () => {
      running = true;
      go.disabled = cancel.disabled = true;
      steps.hidden = false;
      steps.replaceChildren();
      errBox.replaceChildren();
      const s1 = step('Validating the configuration');
      const s2 = step('Writing ' + (app.status && app.status.config.file || 'server.conf'));
      const s3 = step('Restarting the VPN server' + (clients ? ` (${clients} client${clients === 1 ? '' : 's'} will reconnect)` : ''));
      const set = (s, cls, ic) => { s.className = 'step ' + cls; s.firstChild.replaceWith(ic ? icon(ic) : h('span', { class: cls === 'active' ? 'spinner' : 'dot' })); };
      set(s1, 'active');
      const t1 = setTimeout(() => { set(s1, 'done', 'check'); set(s2, 'active'); }, 250);
      const t2 = setTimeout(() => { set(s2, 'done', 'check'); set(s3, 'active'); }, 500);
      try {
        const r = await api('PUT', '/config', { text: newText, hash });
        clearTimeout(t1); clearTimeout(t2);
        [s1, s2, s3].forEach((s) => set(s, 'done', 'check'));
        toast('ok', r.unchanged ? 'Nothing to change' : 'Configuration applied', r.unchanged ? 'The file already has this content.' : 'The server restarted with the new configuration.');
        await app.refreshStatus();
        setTimeout(() => close({ ok: true, hash: r.hash, text: newText }), 500);
      } catch (e) {
        clearTimeout(t1); clearTimeout(t2);
        running = false;
        cancel.disabled = false;
        cancel.textContent = 'Close';
        const b = e instanceof APIError ? e.body : {};
        if (e.status === 422) {
          set(s1, 'failed', 'x');
          s2.remove(); s3.remove();
          close({ ok: false, errors: b.errors || [], message: e.message });
          return;
        }
        if (b.rolledBack !== undefined) {
          set(s1, 'done', 'check'); set(s2, 'done', 'check'); set(s3, 'failed', 'x');
          errBox.append(h('div', { class: 'banner danger' }, icon('alert'), h('div', null,
            h('strong', null, b.rolledBack ? 'The new configuration did not start; the previous one is running again' : 'The server could not be restarted'),
            h('p', null, e.message),
            b.restored ? h('p', null, 'The file was restored to its previous contents.') : null)));
          await app.refreshStatus();
        } else {
          [s1, s2, s3].forEach((s) => { if (!s.classList.contains('done')) set(s, 'failed', 'x'); });
          errBox.append(h('div', { class: 'banner danger' }, icon('alert'), h('div', null, h('strong', null, 'Not applied'), h('p', null, e.message))));
        }
        go.hidden = true;
      }
    };
    return {
      title: opts.title || 'Review and apply', icon: 'refresh', tone: 'warn', wide: true,
      busy: () => running,
      body: [
        opts.intro ? h('p', null, opts.intro) : null,
        h('div', { class: 'split' }, h('span', { class: 'label' }, 'Changes to the file'),
          h('span', { class: 'muted small' }, `${adds} added, ${dels} removed`)),
        diff,
        h('div', { class: 'banner warn' }, icon('alert'), h('div', null,
          h('strong', null, 'The VPN server restarts'),
          h('p', null, clients
            ? `The ${clients} connected client${clients === 1 ? ' is' : 's are'} told to reconnect and should be back within seconds. `
            : 'No clients are connected right now. ',
          'If the new configuration fails to start, the previous one is restored automatically.'))),
        steps, errBox,
      ],
      onSubmit: apply,
      actions: [cancel, go],
    };
  });
}

// changeSettings loads the structured settings, lets mutate() change them,
// and reviews and applies the result. For one-click fixes on other pages.
export async function changeSettings(app, mutate, opts) {
  try {
    const cfg = await api('GET', '/config');
    if (!cfg.writable) { toast('error', 'The configuration is read-only', cfg.reason); return; }
    const settings = cfg.settings;
    mutate(settings);
    const r = await api('POST', '/config/render', { settings, hash: cfg.hash });
    if (!r.changed) { toast('ok', 'Already configured'); return; }
    const res = await reviewAndApply(app, cfg.text, r.text, cfg.hash, opts);
    if (res && res.ok === false) {
      toast('error', 'The change is not valid', (res.errors || []).map((e) => (e.line ? `line ${e.line}: ` : '') + e.message).join('; ') || res.message);
    }
    return res;
  } catch (e) {
    toast('error', 'Could not change the configuration', e.message);
  }
}
