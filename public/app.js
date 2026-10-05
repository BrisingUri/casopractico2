// Todo se pinta con textContent / nodos DOM (nunca innerHTML) para evitar XSS.
const root = document.getElementById('app');
let me = null, tab = 'content', mode = 'login', msg = { t: '', err: false };
const qs = new URLSearchParams(location.search);
if (qs.get('reset')) mode = 'reset';

const el = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) k.startsWith('on') ? e.addEventListener(k.slice(2), v) : (e[k] = v);
  e.append(...kids.flat().filter(x => x != null && x !== false));
  return e;
};
const has = p => me?.perms.includes(p);
const say = (t, err = false) => { msg = { t, err }; };

// Cliente de la API: usa cookies HttpOnly y renueva el access token con el refresh token
async function api(path, method = 'GET', body, retry = true) {
  const r = await fetch('/api' + path, {
    method, credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body && JSON.stringify(body)
  });
  if (r.status === 401 && retry && !path.startsWith('/auth/')) {
    const rf = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'same-origin' });
    if (rf.ok) return api(path, method, body, false);
    me = null; say('Tu sesión expiró. Inicia sesión de nuevo.', true); render();
    throw new Error('Sesión expirada');
  }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || 'Error inesperado');
  return d;
}

// ---------- Autenticación ----------
const FIELDS = {
  login: [['email', 'Correo', 'email'], ['password', 'Contraseña', 'password']],
  register: [['name', 'Nombre', 'text'], ['email', 'Correo', 'email'], ['password', 'Contraseña (8+, mayúscula, minúscula y número)', 'password']],
  forgot: [['email', 'Correo', 'email']],
  reset: [['password', 'Nueva contraseña', 'password']]
};
const TITLES = { login: 'Iniciar sesión', register: 'Crear cuenta', forgot: 'Recuperar contraseña', reset: 'Nueva contraseña' };

function authView() {
  const inputs = FIELDS[mode].map(([n, l, t]) => el('input', {
    name: n, placeholder: l, type: t, required: true, ariaLabel: l,
    autocomplete: n === 'password' ? (mode === 'login' ? 'current-password' : 'new-password') : n
  }));
  const form = el('form', {
    onsubmit: async e => {
      e.preventDefault();
      const b = Object.fromEntries(inputs.map(i => [i.name, i.value]));
      if (mode === 'reset') b.token = qs.get('reset');
      try {
        const d = await api('/auth/' + mode, 'POST', b);
        if (mode === 'login') { me = d.user; say(''); }
        else { say(d.message || 'Listo'); if (mode !== 'forgot') { mode = 'login'; history.replaceState(null, '', '/'); } }
      } catch (er) { say(er.message, true); }
      render();
    }
  }, ...inputs, el('button', {}, TITLES[mode]));
  const link = (m, t) => el('button', { className: 'ghost', type: 'button', onclick: () => { mode = m; say(''); render(); } }, t);
  return el('div', {}, el('h1', {}, TITLES[mode]), form,
    el('p', { className: 'msg' + (msg.err ? ' err' : ''), role: 'status' }, msg.t),
    el('div', { className: 'row' }, mode !== 'login' && link('login', 'Ya tengo cuenta'),
      mode === 'login' && link('register', 'Crear cuenta'), mode === 'login' && link('forgot', 'Olvidé mi contraseña')));
}

// ---------- Contenido ----------
async function contentTab() {
  const items = await api('/content');
  const list = items.length ? items.map(it => el('div', { className: 'card' },
    el('h3', {}, it.title), el('p', {}, it.body),
    el('p', { className: 'mut' }, `${it.author || 'Anónimo'} · ${it.created}`),
    el('div', { className: 'row' },
      has('content:write') && el('button', { className: 'ghost', onclick: async () => {
        const title = prompt('Título', it.title); if (title === null) return;
        const body = prompt('Contenido', it.body); if (body === null) return;
        try { await api('/content/' + it.id, 'PUT', { title, body }); } catch (e) { alert(e.message); }
        render();
      } }, 'Editar'),
      has('content:delete') && el('button', { className: 'danger', onclick: async () => {
        if (!confirm('¿Eliminar este contenido?')) return;
        try { await api('/content/' + it.id, 'DELETE'); } catch (e) { alert(e.message); }
        render();
      } }, 'Eliminar')))) : [el('p', { className: 'mut' }, 'Aún no hay contenido.')];
  const form = has('content:write') && el('form', { className: 'wide', onsubmit: async e => {
    e.preventDefault();
    try { await api('/content', 'POST', { title: e.target.title.value, body: e.target.body.value }); } catch (er) { alert(er.message); }
    render();
  } }, el('h2', {}, 'Nuevo contenido'), el('input', { name: 'title', placeholder: 'Título', required: true, maxLength: 120 }),
    el('textarea', { name: 'body', placeholder: 'Contenido', required: true, rows: 3, maxLength: 2000 }), el('button', {}, 'Publicar'));
  return el('div', {}, form, el('h2', {}, 'Contenido'), ...list);
}

// ---------- Cuenta ----------
function accountTab() {
  const out = el('p', { className: 'msg', role: 'status' });
  return el('form', { onsubmit: async e => {
    e.preventDefault();
    try {
      const d = await api('/auth/change-password', 'POST', { current: e.target.current.value, password: e.target.password.value });
      out.className = 'msg'; out.textContent = d.message; e.target.reset();
    } catch (er) { out.className = 'msg err'; out.textContent = er.message; }
  } }, el('h2', {}, 'Cambiar contraseña'),
    el('input', { name: 'current', type: 'password', placeholder: 'Contraseña actual', required: true, autocomplete: 'current-password' }),
    el('input', { name: 'password', type: 'password', placeholder: 'Nueva contraseña', required: true, autocomplete: 'new-password' }),
    el('button', {}, 'Actualizar contraseña'), out);
}

// ---------- Administración ----------
async function adminTab() {
  const parts = [];
  if (has('users:manage')) {
    const [users, roles] = await Promise.all([api('/admin/users'), has('roles:manage') ? api('/admin/roles') : null]);
    const roleOpts = roles || [...new Map(users.map(u => [u.role_id, { id: u.role_id, name: u.role }])).values()];
    parts.push(el('h2', {}, 'Usuarios'), el('div', { className: 'scroll' }, el('table', {},
      el('tr', {}, ...['Nombre', 'Correo', 'Rol'].map(h => el('th', {}, h))),
      ...users.map(u => el('tr', {}, el('td', {}, u.name), el('td', {}, u.email), el('td', {},
        el('select', { ariaLabel: 'Rol de ' + u.name, onchange: async ev => {
          try { await api(`/admin/users/${u.id}/role`, 'PUT', { role_id: +ev.target.value }); } catch (er) { alert(er.message); }
          render();
        } }, ...roleOpts.map(r => el('option', { value: r.id, selected: r.id === u.role_id }, r.name)))))))));
  }
  if (has('roles:manage')) {
    const [roles, perms] = await Promise.all([api('/admin/roles'), api('/admin/permissions')]);
    const checks = (sel, role) => perms.map(p => el('label', { className: 'chk' },
      el('input', { type: 'checkbox', value: p, checked: role?.permissions.includes(p), disabled: role?.name === 'admin' }), p));
    parts.push(el('h2', {}, 'Roles y permisos'), ...roles.map(r => {
      const box = el('div', {}, ...checks(null, r));
      return el('div', { className: 'card' }, el('h3', {}, r.name), box,
        r.name !== 'admin' && el('button', { onclick: async () => {
          const permissions = [...box.querySelectorAll('input:checked')].map(i => i.value);
          try { await api(`/admin/roles/${r.id}/permissions`, 'PUT', { permissions }); alert('Permisos guardados'); } catch (er) { alert(er.message); }
        } }, 'Guardar permisos'));
    }));
    const box = el('div', {}, ...checks());
    parts.push(el('form', { className: 'wide', onsubmit: async e => {
      e.preventDefault();
      const permissions = [...box.querySelectorAll('input:checked')].map(i => i.value);
      try { await api('/admin/roles', 'POST', { name: e.target.name.value, permissions }); } catch (er) { alert(er.message); }
      render();
    } }, el('h3', {}, 'Crear rol'), el('input', { name: 'name', placeholder: 'Nombre del rol', required: true, maxLength: 30 }), box, el('button', {}, 'Crear rol')));
  }
  if (has('audit:read')) {
    const rows = await api('/admin/audit');
    parts.push(el('h2', {}, 'Registro de auditoría'), el('div', { className: 'scroll' }, el('table', {},
      el('tr', {}, ...['Fecha (UTC)', 'Usuario', 'IP', 'Acción', 'Detalle'].map(h => el('th', {}, h))),
      ...rows.map(r => el('tr', {}, ...[r.ts, r.email || '—', r.ip, r.action, r.detail].map(v => el('td', {}, v ?? '')))))));
  }
  return el('div', {}, ...parts);
}

// ---------- Aplicación principal ----------
async function mainView() {
  const showAdmin = has('users:manage') || has('roles:manage') || has('audit:read');
  const tabs = [['content', 'Contenido'], ['account', 'Mi cuenta'], showAdmin && ['admin', 'Administración']].filter(Boolean);
  if (!tabs.some(t => t[0] === tab)) tab = 'content';
  const body = el('div', {});
  try { body.append(await ({ content: contentTab, account: accountTab, admin: adminTab })[tab]()); }
  catch (e) { if (me) body.append(el('p', { className: 'msg err' }, e.message)); }
  return el('div', {},
    el('header', {}, el('div', {}, el('h1', {}, 'Hola, ' + me.name), el('span', { className: 'mut' }, `Rol: ${me.role}`)),
      el('button', { className: 'ghost', onclick: async () => { await api('/auth/logout', 'POST').catch(() => {}); me = null; say(''); render(); } }, 'Cerrar sesión')),
    el('nav', {}, ...tabs.map(([k, l]) => el('button', { className: 'ghost' + (k === tab ? ' on' : ''), onclick: () => { tab = k; render(); } }, l))),
    body);
}

async function render() { root.replaceChildren(me ? await mainView() : authView()); }

(async () => {
  try { me = (await api('/auth/me')).user; }
  catch {
    try { if ((await fetch('/api/auth/refresh', { method: 'POST', credentials: 'same-origin' })).ok) me = (await api('/auth/me')).user; } catch {}
  }
  render();
})();