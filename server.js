const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const { nanoid } = require("nanoid");

const {
  now,
  normalizeSlug,
  clamp,
  sanitizeCss,
  get,
  all,
  run,
  migrate
} = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || "dev-secret"));
app.use("/public", express.static(path.join(__dirname, "public")));

function uniqueSlug(base) {
  base = normalizeSlug(base);
  if (!base) base = "user";
  return base;
}

async function uniqueSlugEnsure(base) {
  base = uniqueSlug(base);
  let slug = base;
  let i = 2;
  while (await get("SELECT 1 FROM pages WHERE slug = ? LIMIT 1", [slug])) {
    slug = `${base}${i}`;
    i++;
    if (i > 9999) slug = `${base}-${nanoid(6).toLowerCase()}`;
  }
  return slug;
}

async function ensurePageForUser(userId, username) {
  const existing = await get("SELECT user_id FROM pages WHERE user_id = ? LIMIT 1", [userId]);
  if (existing) return;

  const slug = await uniqueSlugEnsure(username);

  await run(
    `INSERT INTO pages (user_id, slug, display_name, bio, avatar_url, bg_url, accent, song_url, song_volume, links_json, custom_css, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      userId,
      slug,
      username,
      "welcome to my page",
      "/public/default-avatar.png",
      "",
      "#8b5cf6",
      "",
      0.4,
      JSON.stringify([]),
      "",
      now()
    ]
  );
}

function validateUsername(u) {
  u = (u || "").toLowerCase().trim();
  if (!u.match(/^[a-z0-9_]{3,20}$/)) return null;
  return u;
}

function validateSlug(s) {
  s = normalizeSlug(s);
  if (!s.match(/^[a-z0-9_-]{2,32}$/)) return null;
  return s;
}

function validateUrl(s) {
  s = (s || "").trim();
  if (!s) return "";
  if (!s.match(/^https?:\/\//i)) return "";
  return s.slice(0, 400);
}

async function getUserFromCookie(req) {
  const token = req.signedCookies.session;
  if (!token) return null;

  const sess = await get("SELECT user_id FROM sessions WHERE token = ? LIMIT 1", [token]);
  if (!sess) return null;

  const user = await get("SELECT id, username, banned, ban_reason FROM users WHERE id = ? LIMIT 1", [sess.user_id]);
  return user || null;
}

async function isImpersonating(req) {
  const token = req.signedCookies.session;
  if (!token) return false;
  const row = await get("SELECT 1 FROM impersonations WHERE token = ? LIMIT 1", [token]);
  return !!row;
}

async function requireAuth(req, res, next) {
  if (!req.user) return res.redirect("/login");
  if (req.user.banned) return res.status(403).send("Banned");
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.user || req.user.id !== 1) return res.status(403).send("Forbidden");
  next();
}

(async () => {
  await migrate();

  app.use(async (req, res, next) => {
    req.user = await getUserFromCookie(req);
    next();
  });

  app.get("/", async (req, res) => {
    if (!req.user) return res.redirect("/login");
    if (req.user.banned) return res.status(403).send("Banned");
    const page = await get("SELECT slug FROM pages WHERE user_id = ? LIMIT 1", [req.user.id]);
    return res.redirect(page ? `/${page.slug}` : "/dashboard");
  });

  app.get("/signup", async (req, res) => {
    res.render("signup", { error: null });
  });

  app.post("/signup", async (req, res) => {
    const username = validateUsername(req.body.username);
    const password = (req.body.password || "").toString();
    const invite = (req.body.invite || "").trim();

    if (!username) return res.render("signup", { error: "Username: 3-20 chars, a-z 0-9 _" });
    if (password.length < 6) return res.render("signup", { error: "Password must be 6+ chars" });

    const inviteRow = await get("SELECT * FROM invite_keys WHERE key = ? LIMIT 1", [invite]);
    if (!inviteRow || inviteRow.used_by) return res.render("signup", { error: "Invalid invite key" });

    const hash = await bcrypt.hash(password, 12);

    try {
      const info = await run(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        [username, hash, now()]
      );

      const userId = Number(info.lastInsertRowid);

      await run("UPDATE invite_keys SET used_by = ?, used_at = ? WHERE key = ?", [userId, now(), invite]);

      await ensurePageForUser(userId, username);

      const token = nanoid(32);
      await run("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", [token, userId, now()]);
      res.cookie("session", token, { signed: true, httpOnly: true, sameSite: "lax" });

      return res.redirect("/dashboard");
    } catch (e) {
      if ((e.message || "").includes("UNIQUE")) return res.render("signup", { error: "Username already taken" });
      return res.render("signup", { error: "Signup failed" });
    }
  });

  app.get("/login", async (req, res) => {
    res.render("login", { error: null });
  });

  app.post("/login", async (req, res) => {
    const username = (req.body.username || "").toLowerCase().trim();
    const password = (req.body.password || "").toString();

    const user = await get("SELECT * FROM users WHERE username = ? LIMIT 1", [username]);
    if (!user) return res.render("login", { error: "Invalid login" });
    if (user.banned) return res.render("login", { error: "Banned" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.render("login", { error: "Invalid login" });

    await ensurePageForUser(user.id, user.username);

    const token = nanoid(32);
    await run("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", [token, user.id, now()]);
    res.cookie("session", token, { signed: true, httpOnly: true, sameSite: "lax" });

    res.redirect("/dashboard");
  });

  app.post("/logout", async (req, res) => {
    const token = req.signedCookies.session;
    if (token) {
      await run("DELETE FROM sessions WHERE token = ?", [token]);
      await run("DELETE FROM impersonations WHERE token = ?", [token]);
    }
    res.clearCookie("session");
    res.redirect("/login");
  });

  app.get("/dashboard", requireAuth, async (req, res) => {
    await ensurePageForUser(req.user.id, req.user.username);

    const page = await get("SELECT * FROM pages WHERE user_id = ? LIMIT 1", [req.user.id]);
    const links = JSON.parse(page.links_json || "[]");

    res.render("dashboard", {
      user: req.user,
      page,
      links,
      error: null,
      ok: null,
      isAdmin: req.user.id === 1,
      impersonating: await isImpersonating(req)
    });
  });

  async function savePageForUser(userId, body) {
    const page = await get("SELECT * FROM pages WHERE user_id = ? LIMIT 1", [userId]);
    if (!page) return { ok: false, error: "No page" };

    const slug = validateSlug(body.slug || page.slug);
    if (!slug) return { ok: false, error: "Slug must be 2-32: a-z 0-9 _ -" };

    const owner = await get("SELECT user_id FROM pages WHERE slug = ? LIMIT 1", [slug]);
    if (owner && owner.user_id !== userId) return { ok: false, error: "That slug is taken" };

    const links = [];
    for (let i = 0; i < 14; i++) {
      const label = (body[`label_${i}`] || "").trim().slice(0, 32);
      const url = validateUrl(body[`url_${i}`] || "");
      if (!label && !url) continue;
      if (!url) continue;
      links.push({ label: label || "Link", url });
    }

    const displayName = (body.display_name || "").trim().slice(0, 40);
    const bio = (body.bio || "").trim().slice(0, 240);
    const avatarUrl = (body.avatar_url || "").trim().slice(0, 400) || "/public/default-avatar.png";
    const bgUrl = (body.bg_url || "").trim().slice(0, 400);
    const accent = (body.accent || "#8b5cf6").trim().slice(0, 16);
    const songUrl = (body.song_url || "").trim().slice(0, 400);
    const songVolume = clamp(body.song_volume, 0, 1);
    const customCss = sanitizeCss(body.custom_css || "");

    await run(
      `UPDATE pages
       SET slug = ?, display_name = ?, bio = ?, avatar_url = ?, bg_url = ?, accent = ?, song_url = ?, song_volume = ?, links_json = ?, custom_css = ?, updated_at = ?
       WHERE user_id = ?`,
      [
        slug,
        displayName,
        bio,
        avatarUrl,
        bgUrl,
        accent,
        songUrl,
        songVolume,
        JSON.stringify(links),
        customCss,
        now(),
        userId
      ]
    );

    return { ok: true };
  }

  app.post("/dashboard", requireAuth, async (req, res) => {
    const result = await savePageForUser(req.user.id, req.body);

    const page = await get("SELECT * FROM pages WHERE user_id = ? LIMIT 1", [req.user.id]);
    const links = JSON.parse(page.links_json || "[]");

    res.render("dashboard", {
      user: req.user,
      page,
      links,
      error: result.ok ? null : result.error,
      ok: result.ok ? "Saved" : null,
      isAdmin: req.user.id === 1,
      impersonating: await isImpersonating(req)
    });
  });

  app.get("/admin", requireAuth, requireAdmin, async (req, res) => res.redirect("/admin/keys"));

  app.get("/admin/keys", requireAuth, requireAdmin, async (req, res) => {
    const keys = await all("SELECT * FROM invite_keys ORDER BY created_at DESC LIMIT 80");
    res.render("admin_keys", { user: req.user, keys });
  });

  app.post("/admin/keys", requireAuth, requireAdmin, async (req, res) => {
    const k = nanoid(10).toUpperCase();
    await run("INSERT INTO invite_keys (key, created_by, created_at) VALUES (?, ?, ?)", [k, req.user.id, now()]);
    res.redirect("/admin/keys");
  });

  app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
    const users = await all(
      `SELECT u.id, u.username, u.banned, u.ban_reason, u.created_at, p.slug
       FROM users u
       LEFT JOIN pages p ON p.user_id = u.id
       ORDER BY u.id ASC
       LIMIT 1000`
    );
    res.render("admin_users", { user: req.user, users });
  });

  app.post("/admin/users/:id/ban", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!id || id === 1) return res.status(400).send("no");
    const reason = (req.body.reason || "").toString().slice(0, 120);
    await run("UPDATE users SET banned = 1, ban_reason = ? WHERE id = ?", [reason, id]);
    res.redirect("/admin/users");
  });

  app.post("/admin/users/:id/unban", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!id || id === 1) return res.status(400).send("no");
    await run("UPDATE users SET banned = 0, ban_reason = '' WHERE id = ?", [id]);
    res.redirect("/admin/users");
  });

  app.post("/admin/impersonate/:id", requireAuth, requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send("no");

    const target = await get("SELECT id FROM users WHERE id = ? LIMIT 1", [id]);
    if (!target) return res.status(404).send("not found");

    const token = nanoid(32);
    await run("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", [token, id, now()]);
    await run("INSERT INTO impersonations (token, admin_user_id, created_at) VALUES (?, ?, ?)", [token, req.user.id, now()]);

    res.cookie("session", token, { signed: true, httpOnly: true, sameSite: "lax" });
    res.redirect("/dashboard");
  });

  app.post("/admin/return", requireAuth, async (req, res) => {
    const token = req.signedCookies.session;
    if (!token) return res.redirect("/dashboard");

    const row = await get("SELECT admin_user_id FROM impersonations WHERE token = ? LIMIT 1", [token]);
    if (!row) return res.redirect("/dashboard");

    await run("DELETE FROM sessions WHERE token = ?", [token]);
    await run("DELETE FROM impersonations WHERE token = ?", [token]);

    const newToken = nanoid(32);
    await run("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", [newToken, row.admin_user_id, now()]);
    res.cookie("session", newToken, { signed: true, httpOnly: true, sameSite: "lax" });

    res.redirect("/admin/users");
  });

  app.get("/:slug", async (req, res) => {
    const slug = normalizeSlug(req.params.slug);
    const page = await get("SELECT * FROM pages WHERE slug = ? LIMIT 1", [slug]);
    if (!page) return res.status(404).send("Not found");
    const links = JSON.parse(page.links_json || "[]");
    res.render("profile", { page, links });
  });

  app.listen(PORT, () => {
    console.log("running on http://localhost:" + PORT);
  });
})();