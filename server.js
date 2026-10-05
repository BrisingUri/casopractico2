const express = require('express'), helmet = require('helmet'), cors = require('cors'),
  cookieParser = require('cookie-parser'), rateLimit = require('express-rate-limit'),
  jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs'), crypto = require('crypto'),
  Database = require('better-sqlite3');

const { JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, ORIGIN = 'http://localhost:3000', PORT = 3000, NODE_ENV } = process.env;
if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('Define JWT_SECRET (min. 32 caracteres) en .env'); process.exit(1); }

// ---------- Base de datos ----------
const db = new Database('app.db');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS roles(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS permissions(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS role_permissions(
  role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
  permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY(role_id, permission_id));
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role_id INTEGER NOT NULL REFERENCES roles(id),
  failed INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contents(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
  author_id INTEGER REFERENCES users(id), created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT DEFAULT CURRENT_TIMESTAMP,
  user_id INTEGER, ip TEXT, action TEXT, detail TEXT);
-- La bitácora no se puede modificar ni borrar desde la aplicación
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit inmutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit inmutable'); END;
`);

const PERMS = ['content:read', 'content:write', 'content:delete', 'users:manage', 'roles:manage', 'audit:read'];
const SEED = { admin: PERMS, editor: ['content:read', 'content:write', 'content:delete'], user: ['content:read'] };
if (!db.prepare('SELECT 1 FROM roles').get()) {
  db.transaction(() => {
    PERMS.forEach(p => db.prepare('INSERT INTO permissions(name) VALUES(?)').run(p));
    for (const [r, ps] of Object.entries(SEED)) {
      const rid = db.prepare('INSERT INTO roles(name) VALUES(?)').run(r).lastInsertRowid;
      ps.forEach(p => db.prepare('INSERT INTO role_permissions SELECT ?, id FROM permissions WHERE name=?').run(rid, p));
    }
    if (ADMIN_EMAIL && ADMIN_PASSWORD)
      db.prepare('INSERT INTO users(name,email,password_hash,role_id) VALUES(?,?,?,(SELECT id FROM roles WHERE name=\'admin\'))')
        .run('Administrador', ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(ADMIN_PASSWORD, 12));
  })();
}

// ---------- Utilidades ----------
const USER = 'SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id=u.role_id';
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const DUMMY = bcrypt.hashSync('dummy-password', 12); // iguala tiempos cuando el email no existe
const permsOf = roleId => db.prepare('SELECT p.name FROM permissions p JOIN role_permissions rp ON rp.permission_id=p.id WHERE rp.role_id=?')
  .all(roleId).map(r => r.name);
const log = (req, action, detail = '', uid = req.user?.id) =>
  db.prepare('INSERT INTO audit(user_id,ip,action,detail) VALUES(?,?,?,?)').run(uid ?? null, req.ip, action, String(detail).slice(0, 300));

const str = (v, min, max) => typeof v === 'string' && v.trim().length >= min && v.length <= max;
const emailOk = v => str(v, 5, 254) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const pwOk = v => str(v, 8, 72) && /[a-z]/.test(v) && /[A-Z]/.test(v) && /\d/.test(v);
const bad = (res, m = 'Datos inválidos') => res.status(400).json({ error: m });
const idOk = v => Number.isInteger(+v) && +v > 0;

const cookieBase = { httpOnly: true, secure: NODE_ENV === 'production', sameSite: 'strict' };
function issueTokens(res, u) {
  const access = jwt.sign({ sub: u.id, role: u.role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '15m' });
  const refresh = crypto.randomBytes(48).toString('hex');
  db.prepare('INSERT INTO tokens VALUES(?,?,?,?)').run(sha(refresh), u.id, 'refresh', Date.now() + 7 * 864e5);
  res.cookie('access', access, { ...cookieBase, maxAge: 15 * 60e3 });
  res.cookie('refresh', refresh, { ...cookieBase, path: '/api/auth', maxAge: 7 * 864e5 });
  return access;
}
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, perms: permsOf(u.role_id) });

// ---------- Middlewares ----------
const auth = (req, res, next) => {
  const h = req.headers.authorization;
  const token = h?.startsWith('Bearer ') ? h.slice(7) : req.cookies.access;
  try {
    const p = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); // valida firma y expiración
    const u = db.prepare(USER + ' WHERE u.id=?').get(p.sub);
    if (!u) throw new Error();
    req.user = publicUser(u); // permisos leídos de la BD: los cambios de rol aplican de inmediato
    next();
  } catch { res.status(401).json({ error: 'No autenticado' }); }
};
const need = perm => (req, res, next) => req.user.perms.includes(perm) ? next()
  : (log(req, 'ACCESS_DENIED', `${req.method} ${req.originalUrl} requiere ${perm}`), res.status(403).json({ error: 'Permiso insuficiente' }));
const authLimit = rateLimit({ windowMs: 15 * 60e3, limit: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes, intenta más tarde' } });

// ---------- App ----------
const app = express();
app.use(helmet());
app.use(cors({ origin: ORIGIN, credentials: true })); // solo el origen autorizado
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static('public'));

// ----- Autenticación -----
const a = express.Router();
a.post('/register', authLimit, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!str(name, 2, 80) || !emailOk(email) || !pwOk(password))
    return bad(res, 'Revisa los datos: contraseña de 8+ caracteres con mayúscula, minúscula y número');
  try {
    const id = db.prepare("INSERT INTO users(name,email,password_hash,role_id) VALUES(?,?,?,(SELECT id FROM roles WHERE name='user'))")
      .run(name.trim(), email.toLowerCase(), await bcrypt.hash(password, 12)).lastInsertRowid;
    log(req, 'REGISTER', email, id);
  } catch { /* email duplicado: misma respuesta para no revelar si existe */ }
  res.status(201).json({ message: 'Registro procesado' });
});

a.post('/login', authLimit, async (req, res) => {
  const { email, password } = req.body || {};
  if (!emailOk(email) || !str(password, 1, 72)) return bad(res);
  const u = db.prepare(USER + ' WHERE u.email=?').get(email.toLowerCase());
  const fail = () => res.status(401).json({ error: 'Credenciales inválidas' });
  if (!u) { await bcrypt.compare(password, DUMMY); log(req, 'LOGIN_FAIL', email); return fail(); }
  if (u.locked_until > Date.now()) { log(req, 'LOGIN_LOCKED', email, u.id); return res.status(429).json({ error: 'Cuenta bloqueada temporalmente. Intenta en 15 minutos' }); }
  if (!(await bcrypt.compare(password, u.password_hash))) {
    const f = u.failed + 1;
    db.prepare('UPDATE users SET failed=?, locked_until=? WHERE id=?').run(f >= 5 ? 0 : f, f >= 5 ? Date.now() + 15 * 60e3 : 0, u.id);
    log(req, f >= 5 ? 'ACCOUNT_LOCKED' : 'LOGIN_FAIL', email, u.id);
    return fail();
  }
  db.prepare('UPDATE users SET failed=0, locked_until=0 WHERE id=?').run(u.id);
  const accessToken = issueTokens(res, u);
  log(req, 'LOGIN_OK', '', u.id);
  res.json({ user: publicUser(u), accessToken }); // accessToken también sirve como Authorization: Bearer
});

a.post('/refresh', (req, res) => {
  const rt = req.cookies.refresh;
  const row = rt && db.prepare("SELECT * FROM tokens WHERE hash=? AND type='refresh' AND expires>?").get(sha(rt), Date.now());
  if (!row) return res.status(401).json({ error: 'Sesión expirada' });
  db.prepare('DELETE FROM tokens WHERE hash=?').run(row.hash); // rotación del refresh token
  issueTokens(res, db.prepare(USER + ' WHERE u.id=?').get(row.user_id));
  res.json({ ok: true });
});

a.post('/logout', (req, res) => {
  const rt = req.cookies.refresh;
  const row = rt && db.prepare('SELECT user_id FROM tokens WHERE hash=?').get(sha(rt));
  if (rt) db.prepare('DELETE FROM tokens WHERE hash=?').run(sha(rt));
  if (row) log(req, 'LOGOUT', '', row.user_id);
  res.clearCookie('access', cookieBase).clearCookie('refresh', { ...cookieBase, path: '/api/auth' }).json({ ok: true });
});

a.get('/me', auth, (req, res) => res.json({ user: req.user }));

a.post('/change-password', auth, async (req, res) => {
  const { current, password } = req.body || {};
  if (!str(current, 1, 72) || !pwOk(password)) return bad(res);
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!(await bcrypt.compare(current, u.password_hash))) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(password, 12), u.id);
  db.prepare("DELETE FROM tokens WHERE user_id=? AND type='refresh'").run(u.id);
  log(req, 'PASSWORD_CHANGED');
  res.json({ message: 'Contraseña actualizada' });
});

a.post('/forgot', authLimit, (req, res) => {
  const { email } = req.body || {};
  const u = emailOk(email) && db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase());
  if (u) {
    const t = crypto.randomBytes(32).toString('hex');
    db.prepare("INSERT INTO tokens VALUES(?,?,'reset',?)").run(sha(t), u.id, Date.now() + 30 * 60e3);
    log(req, 'PASSWORD_RESET_REQUEST', '', u.id);
    // En producción: enviar por correo. En desarrollo se imprime en consola.
    console.log(`[DEV] Enlace de recuperación: ${ORIGIN}/?reset=${t}`);
  }
  res.json({ message: 'Si el correo existe, recibirás instrucciones para restablecer la contraseña' });
});

a.post('/reset', authLimit, async (req, res) => {
  const { token, password } = req.body || {};
  if (!str(token, 64, 64) || !pwOk(password)) return bad(res);
  const row = db.prepare("SELECT * FROM tokens WHERE hash=? AND type='reset' AND expires>?").get(sha(token), Date.now());
  if (!row) return bad(res, 'Enlace inválido o expirado');
  db.prepare('UPDATE users SET password_hash=?, failed=0, locked_until=0 WHERE id=?').run(await bcrypt.hash(password, 12), row.user_id);
  db.prepare('DELETE FROM tokens WHERE user_id=?').run(row.user_id); // invalida reset y sesiones
  log(req, 'PASSWORD_RESET', '', row.user_id);
  res.json({ message: 'Contraseña restablecida' });
});
app.use('/api/auth', a);

// ----- Contenido -----
const c = express.Router();
c.use(auth);
c.get('/', need('content:read'), (req, res) =>
  res.json(db.prepare('SELECT c.id,c.title,c.body,c.created,u.name AS author FROM contents c LEFT JOIN users u ON u.id=c.author_id ORDER BY c.id DESC').all()));
c.post('/', need('content:write'), (req, res) => {
  const { title, body } = req.body || {};
  if (!str(title, 1, 120) || !str(body, 1, 2000)) return bad(res);
  const id = db.prepare('INSERT INTO contents(title,body,author_id) VALUES(?,?,?)').run(title.trim(), body.trim(), req.user.id).lastInsertRowid;
  log(req, 'CONTENT_CREATE', id); res.status(201).json({ id });
});
c.put('/:id', need('content:write'), (req, res) => {
  const { title, body } = req.body || {};
  if (!idOk(req.params.id) || !str(title, 1, 120) || !str(body, 1, 2000)) return bad(res);
  const r = db.prepare('UPDATE contents SET title=?, body=? WHERE id=?').run(title.trim(), body.trim(), req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'No encontrado' });
  log(req, 'CONTENT_UPDATE', req.params.id); res.json({ ok: true });
});
c.delete('/:id', need('content:delete'), (req, res) => {
  if (!idOk(req.params.id)) return bad(res);
  const r = db.prepare('DELETE FROM contents WHERE id=?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'No encontrado' });
  log(req, 'CONTENT_DELETE', req.params.id); res.json({ ok: true });
});
app.use('/api/content', c);

// ----- Administración -----
const ad = express.Router();
ad.use(auth);
ad.get('/users', need('users:manage'), (req, res) =>
  res.json(db.prepare('SELECT u.id,u.name,u.email,u.role_id,r.name AS role FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id').all()));
ad.put('/users/:id/role', need('users:manage'), (req, res) => {
  const { role_id } = req.body || {};
  if (!idOk(req.params.id) || !idOk(role_id) || !db.prepare('SELECT 1 FROM roles WHERE id=?').get(role_id)) return bad(res);
  if (+req.params.id === req.user.id) return bad(res, 'No puedes cambiar tu propio rol');
  const r = db.prepare('UPDATE users SET role_id=? WHERE id=?').run(role_id, req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'No encontrado' });
  log(req, 'ROLE_ASSIGN', `usuario ${req.params.id} -> rol ${role_id}`); res.json({ ok: true });
});
ad.get('/permissions', need('roles:manage'), (req, res) => res.json(PERMS));
ad.get('/roles', need('roles:manage'), (req, res) =>
  res.json(db.prepare('SELECT * FROM roles').all().map(r => ({ ...r, permissions: permsOf(r.id) }))));
const setPerms = (rid, list) => db.transaction(() => {
  db.prepare('DELETE FROM role_permissions WHERE role_id=?').run(rid);
  list.forEach(p => db.prepare('INSERT INTO role_permissions SELECT ?, id FROM permissions WHERE name=?').run(rid, p));
})();
const permsValid = l => Array.isArray(l) && l.every(p => PERMS.includes(p));
ad.post('/roles', need('roles:manage'), (req, res) => {
  const { name, permissions = [] } = req.body || {};
  if (typeof name !== 'string' || !/^[\wáéíóúñ -]{2,30}$/i.test(name) || !permsValid(permissions)) return bad(res);
  try {
    const rid = db.prepare('INSERT INTO roles(name) VALUES(?)').run(name.trim()).lastInsertRowid;
    setPerms(rid, permissions); log(req, 'ROLE_CREATE', name); res.status(201).json({ id: rid });
  } catch { bad(res, 'El rol ya existe'); }
});
ad.put('/roles/:id/permissions', need('roles:manage'), (req, res) => {
  const role = idOk(req.params.id) && db.prepare('SELECT * FROM roles WHERE id=?').get(req.params.id);
  if (!role || !permsValid(req.body?.permissions)) return bad(res);
  if (role.name === 'admin') return bad(res, 'El rol administrador no se puede modificar');
  setPerms(role.id, req.body.permissions); log(req, 'ROLE_PERMISSIONS', `${role.name}: ${req.body.permissions.join(',')}`);
  res.json({ ok: true });
});
ad.get('/audit', need('audit:read'), (req, res) =>
  res.json(db.prepare('SELECT a.id,a.ts,a.ip,a.action,a.detail,u.email FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200').all()));
app.use('/api/admin', ad);

// ----- Errores sin fuga de información -----
app.use('/api', (req, res) => res.status(404).json({ error: 'Recurso no encontrado' }));
app.use((err, req, res, next) => {
  console.error(err); // el detalle solo queda en el servidor
  res.status(err.type ? 400 : 500).json({ error: err.type ? 'Solicitud inválida' : 'Error interno' });
});

app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));