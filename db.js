const { createClient } = require("@libsql/client");

let client = null;

function getClient() {
  if (client) return client;

  const url = process.env.TURSO_DATABASE_URL;
  const authToken = process.env.TURSO_AUTH_TOKEN;

  if (!url || !authToken) {
    throw new Error("Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN");
  }

  client = createClient({ url, authToken });
  return client;
}

function now() {
  return new Date().toISOString();
}

function normalizeSlug(s) {
  return (s || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_-]/g, "")
    .slice(0, 32);
}

function clamp(n, a, b) {
  n = Number(n);
  if (Number.isNaN(n)) return a;
  return Math.max(a, Math.min(b, n));
}

function sanitizeCss(css) {
  css = (css || "").toString();
  css = css.replace(/<\/style/gi, "");
  css = css.replace(/<script/gi, "");
  css = css.replace(/@import/gi, "");
  return css.slice(0, 6000);
}

async function exec(sql, args = []) {
  const c = getClient();
  return c.execute({ sql, args });
}

async function get(sql, args = []) {
  const r = await exec(sql, args);
  return r.rows && r.rows.length ? r.rows[0] : null;
}

async function all(sql, args = []) {
  const r = await exec(sql, args);
  return r.rows || [];
}

async function run(sql, args = []) {
  const r = await exec(sql, args);
  return { rowsAffected: r.rowsAffected || 0, lastInsertRowid: r.lastInsertRowid };
}

async function migrate() {
  await exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      banned INTEGER NOT NULL DEFAULT 0,
      ban_reason TEXT NOT NULL DEFAULT ''
    )
  `);

  await exec(`
    CREATE TABLE IF NOT EXISTS pages (
      user_id INTEGER PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL DEFAULT '',
      bio TEXT NOT NULL DEFAULT '',
      avatar_url TEXT NOT NULL DEFAULT '',
      bg_url TEXT NOT NULL DEFAULT '',
      accent TEXT NOT NULL DEFAULT '#8b5cf6',
      song_url TEXT NOT NULL DEFAULT '',
      song_volume REAL NOT NULL DEFAULT 0.4,
      links_json TEXT NOT NULL DEFAULT '[]',
      custom_css TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await exec(`
    CREATE TABLE IF NOT EXISTS invite_keys (
      key TEXT PRIMARY KEY,
      created_by INTEGER NOT NULL,
      used_by INTEGER,
      used_at TEXT,
      created_at TEXT NOT NULL
    )
  `);

  await exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  await exec(`
    CREATE TABLE IF NOT EXISTS impersonations (
      token TEXT PRIMARY KEY,
      admin_user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
}

module.exports = { now, normalizeSlug, clamp, sanitizeCss, exec, get, all, run, migrate };
