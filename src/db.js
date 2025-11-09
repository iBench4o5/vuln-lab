const { Pool } = require('pg');

const rawUrl = process.env.DATABASE_URL;

// create pool (Supabase treba SSL)
const pool = new Pool({
  connectionString: rawUrl,
  ssl: { rejectUnauthorized: false }
});

// ---- utility: pretty print URL bez kredencijala
function maskDbUrl(url) {
  try {
    const u = new URL(url);
    u.username = '<user>';
    u.password = '<pass>';
    return u.toString();
  } catch {
    return '<invalid DATABASE_URL>';
  }
}

// ---- verify connection once at startup
async function verifyDbConnection() {
  const masked = maskDbUrl(rawUrl);
  try {
    const r = await pool.query('select 1 as ok');
    console.log(`✅ DB connected (${masked})`);
    return true;
  } catch (e) {
    console.error(`❌ DB connection FAILED (${masked})`);
    console.error(e.message);
    return false;
  }
}

pool.on('error', (err) => {
  console.error('PG Pool error:', err.message);
});

module.exports = { pool, verifyDbConnection };
