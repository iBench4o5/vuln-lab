// server.js
require('dotenv').config(); // MORA biti prva linija

const express = require('express');
const session = require('express-session');
const path = require('path');
const csrf = require('csurf');
const engine = require('ejs-mate');

const app = express();
const PORT = process.env.PORT || 3000;

// ----- In-memory toggles (UI prekidači) -----
const toggles = {
  sqliVulnerable: true,   // ON = ranjivo (string concat)
  csrfVulnerable: true    // ON = ranjivo (bez CSRF tokena)
};

// Trust proxy for secure cookies on Render
app.set('trust proxy', 1);

// View engine & static
app.engine('ejs', engine);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src', 'views'));
app.use('/public', express.static(path.join(__dirname, 'src', 'public')));

const { pool, verifyDbConnection } = require('./src/db');
verifyDbConnection();

// Parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (SameSite None u produkciji da bismo mogli demonstrirati pravi CSRF)
const isProd = process.env.NODE_ENV === 'production';
app.use(session({
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProd,                 // na Renderu true (HTTPS), lokalno false
    sameSite: isProd ? 'none' : 'lax'
  }
}));

// Dynamic CSRF protection: uključena samo kad je toggles.csrfVulnerable = false
const csurfMiddleware = csrf();
app.use((req, res, next) => {
  if (toggles.csrfVulnerable) return next();     // ranjivo: bez CSRF zaštite
  return csurfMiddleware(req, res, next);        // sigurno: traži CSRF token
});

// Make toggles & user visible in all templates
app.use((req, res, next) => {
  res.locals.toggles = toggles;
  res.locals.user = req.session.user || null;
  next();
});

// ----- Helpers -----
async function findUserUnsafe(username, password) {
  // RANJIVO: string konkatenacija -> SQL Injection (tautology)
  const text = `
    SELECT id, username, email FROM users
    WHERE username = '${username}' AND password = '${password}'
    LIMIT 1;
  `;
  // (Opcionalno) console.log('UNSAFE SQL:', text);
  return pool.query(text);
}

async function findUserSafe(username, password) {
  // SIGURNO: parametrizirani upit
  const text = `
    SELECT id, username, email FROM users
    WHERE username = $1 AND password = $2
    LIMIT 1;
  `;
  return pool.query(text, [username, password]);
}

// ----- Routes -----

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/dashboard', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { rows } = await pool.query('SELECT id, username, email, bio FROM users WHERE id = $1', [req.session.user.id]);
  res.render('dashboard', { me: rows[0] });
});

// Admin toggles page
app.get('/admin', (req, res) => {
  res.render('admin');
});

app.get('/admin/toggles', (req, res) => {
  toggles.sqliVulnerable = !!req.query.sqliVulnerable;
  toggles.csrfVulnerable = !!req.query.csrfVulnerable;
  res.redirect('/admin');
});


// Login demo (SQLi)
app.get('/login', (req, res) => {
  res.render('login', {
    helpExample: `' OR '1'='1`
  });
});

app.post('/login', async (req, res) => {
  const { username = '', password = '' } = req.body;

  try {
    let result;
    if (toggles.sqliVulnerable) {
      result = await findUserUnsafe(username, password);
    } else {
      result = await findUserSafe(username, password);
    }

    if (result.rows.length) {
      req.session.user = {
        id: result.rows[0].id,
        username: result.rows[0].username,
        email: result.rows[0].email
      };
      return res.redirect('/dashboard');
    }
    return res.status(401).send('Login failed');
  } catch (e) {
    console.error(e);
    return res.status(500).send('Server error');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Profile (CSRF demo target)
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  // CSRF token je dostupan samo kad je zaštita uključena
  const csrfToken = (!toggles.csrfVulnerable && req.csrfToken) ? req.csrfToken() : null;
  res.render('profile', { csrfToken });
});

app.post('/profile/email', async (req, res) => {
  if (!req.session.user) return res.status(401).send('Not logged in');

  // Ako je CSRF zaštita uključena, csurf middleware će automatski odbiti (403) bez ispravnog tokena.
  const { email = '' } = req.body;

  try {
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [email, req.session.user.id]);
    return res.redirect('/dashboard');
  } catch (e) {
    console.error(e);
    return res.status(500).send('Server error');
  }
});

// CSRF demo preko GET (namjerno loše): radi SAMO kad je VULNERABLE = ON
app.get('/profile/email/change', async (req, res) => {
  if (!req.session.user) return res.status(401).send('Not logged in');
  if (!toggles.csrfVulnerable) return res.status(405).send('Disabled in SAFE mode');

  const email = req.query.email || '';
  try {
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [email, req.session.user.id]);
    return res.redirect('/dashboard');
  } catch (e) {
    console.error(e);
    return res.status(500).send('Server error');
  }
});

// Attacker helper page (generira data: URL za cross-site POST i GET)
app.get('/attacker', (req, res) => {
  // action je apsolutni URL na ovu aplikaciju (POST meta)
  const host = req.get('host');
  const proto = req.protocol; // na Renderu će biti https
  const action = `${proto}://${host}/profile/email`;

  // e-mail koji "napadač" želi postaviti
  const maliciousEmail = 'pwned+' + Date.now() + '@evil.example';

  // POST varijanta (pravi CSRF kroz auto-submit formu)
  const attackHtml = [
    '<!doctype html><html><body>',
    '<h3>External attacker page (POST)</h3>',
    `<form id="f" action="${action}" method="POST">`,
    `<input type="hidden" name="email" value="${maliciousEmail}">`,
    '</form>',
    '<script>document.getElementById("f").submit();</script>',
    '</body></html>'
  ].join('');
  const dataUrl = 'data:text/html;base64,' + Buffer.from(attackHtml, 'utf8').toString('base64');

  // GET varijanta (za lokalnu demonstraciju s Lax kolačićem)
  const getAttackUrl = `${proto}://${host}/profile/email/change?email=${encodeURIComponent(maliciousEmail)}`;
  const getAttackHtml = `<!doctype html><meta http-equiv="refresh" content="0;url=${getAttackUrl}">Redirecting...`;
  const dataUrlGet = 'data:text/html;base64,' + Buffer.from(getAttackHtml, 'utf8').toString('base64');

  res.render('attacker', { dataUrl, dataUrlGet, maliciousEmail, action });
});

// (opcionalno) health check
app.get('/healthz', async (_req, res) => {
  try {
    const r = await pool.query('select 1 as ok');
    res.send('db ok: ' + r.rows[0].ok);
  } catch (e) {
    console.error(e);
    res.status(500).send('db error: ' + e.message);
  }
});

// 404
app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => {
  console.log(`Listening on http://localhost:${PORT}`);
});
