const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const db = new Database("data.db");

async function run() {
  const username = "iqsm";
  const password = "Indi2017!!::";

  const hash = await bcrypt.hash(password, 12);

  const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (existing) {
    console.log("user already exists with id", existing.id);
    return;
  }

  const info = db.prepare(`
    INSERT INTO users (username, password_hash, created_at)
    VALUES (?, ?, ?)
  `).run(username, hash, new Date().toISOString());

  console.log("admin created with id", info.lastInsertRowid);
}

run();