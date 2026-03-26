const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const webpush = require("web-push");
const Database = require("better-sqlite3");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" }, maxHttpBufferSize: 1e8 });

app.use(cors());
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "spark.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    phone TEXT UNIQUE,
    password TEXT NOT NULL,
    avatar_color TEXT DEFAULT '#25D366',
    avatar_img TEXT,
    status TEXT DEFAULT 'Hey there! I am using Spark Messenger.',
    about TEXT DEFAULT '',
    language TEXT DEFAULT 'en',
    last_seen INTEGER DEFAULT (strftime('%s','now') * 1000),
    is_online INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS contacts (
    user_id TEXT NOT NULL, contact_id TEXT NOT NULL,
    nickname TEXT DEFAULT '',
    PRIMARY KEY (user_id, contact_id)
  );
  CREATE TABLE IF NOT EXISTS blocked (
    user_id TEXT NOT NULL, blocked_id TEXT NOT NULL,
    PRIMARY KEY (user_id, blocked_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    from_user_id TEXT NOT NULL,
    to_user_id TEXT NOT NULL,
    content TEXT DEFAULT '',
    type TEXT DEFAULT 'text',
    file_url TEXT, file_name TEXT, file_size INTEGER, file_mime TEXT,
    reply_to TEXT,
    reactions TEXT DEFAULT '{}',
    timestamp INTEGER DEFAULT (strftime('%s','now') * 1000),
    is_read INTEGER DEFAULT 0,
    is_deleted INTEGER DEFAULT 0,
    edited INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id);
  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, admin_id TEXT NOT NULL,
    avatar_color TEXT DEFAULT '#25D366', avatar_img TEXT,
    description TEXT DEFAULT '',
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL, user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    PRIMARY KEY (group_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS group_messages (
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL, from_user_id TEXT NOT NULL,
    content TEXT DEFAULT '', type TEXT DEFAULT 'text',
    file_url TEXT, file_name TEXT, file_size INTEGER, file_mime TEXT,
    reply_to TEXT,
    reactions TEXT DEFAULT '{}',
    timestamp INTEGER DEFAULT (strftime('%s','now') * 1000),
    is_deleted INTEGER DEFAULT 0,
    edited INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_gmsg_group ON group_messages(group_id);
  CREATE TABLE IF NOT EXISTS statuses (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
    content TEXT NOT NULL, type TEXT DEFAULT 'text',
    caption TEXT DEFAULT '',
    views TEXT DEFAULT '[]',
    timestamp INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS pinned_chats (
    user_id TEXT NOT NULL, chat_id TEXT NOT NULL,
    PRIMARY KEY (user_id, chat_id)
  );
  CREATE TABLE IF NOT EXISTS archived_chats (
    user_id TEXT NOT NULL, chat_id TEXT NOT NULL,
    PRIMARY KEY (user_id, chat_id)
  );
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    user_id TEXT PRIMARY KEY, subscription TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS message_drafts (
    user_id TEXT NOT NULL, chat_id TEXT NOT NULL, content TEXT DEFAULT '',
    PRIMARY KEY (user_id, chat_id)
  );
  CREATE TABLE IF NOT EXISTS user_settings (
    user_id TEXT PRIMARY KEY,
    notification_sound INTEGER DEFAULT 1,
    notification_vibrate INTEGER DEFAULT 1,
    read_receipts INTEGER DEFAULT 1,
    last_seen_visible INTEGER DEFAULT 1,
    wallpaper TEXT DEFAULT '',
    font_size TEXT DEFAULT 'medium',
    enter_to_send INTEGER DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS scheduled_messages (
    id TEXT PRIMARY KEY,
    from_user_id TEXT NOT NULL,
    to_user_id TEXT,
    group_id TEXT,
    content TEXT NOT NULL,
    type TEXT DEFAULT 'text',
    send_at INTEGER NOT NULL,
    sent INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS polls (
    id TEXT PRIMARY KEY,
    group_id TEXT,
    room_id TEXT,
    creator_id TEXT NOT NULL,
    question TEXT NOT NULL,
    options TEXT NOT NULL,
    votes TEXT DEFAULT '{}',
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
`);

// Migrate: add missing columns safely
const addColumnSafe = (table, col, def) => {
  try { db.prepare(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`).run(); } catch(e) {}
};
addColumnSafe('users', 'phone', 'TEXT');
addColumnSafe('messages', 'reply_to', 'TEXT');
addColumnSafe('messages', 'reactions', "TEXT DEFAULT '{}'");
addColumnSafe('messages', 'edited', 'INTEGER DEFAULT 0');
addColumnSafe('group_messages', 'reply_to', 'TEXT');
addColumnSafe('group_messages', 'reactions', "TEXT DEFAULT '{}'");
addColumnSafe('group_messages', 'edited', 'INTEGER DEFAULT 0');
addColumnSafe('statuses', 'caption', "TEXT DEFAULT ''");
addColumnSafe('statuses', 'views', "TEXT DEFAULT '[]'");
addColumnSafe('contacts', 'nickname', "TEXT DEFAULT ''");
addColumnSafe('group_members', 'role', "TEXT DEFAULT 'member'");
addColumnSafe('users', 'last_seen', 'INTEGER DEFAULT 0');
addColumnSafe('users', 'is_online', 'INTEGER DEFAULT 0');

const JWT_SECRET = process.env.JWT_SECRET || "sparkmessenger_v5_secret";
let VAPID_PUBLIC = process.env.VAPID_PUBLIC;
let VAPID_PRIVATE = process.env.VAPID_PRIVATE;
if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
  const keys = webpush.generateVAPIDKeys();
  VAPID_PUBLIC = keys.publicKey;
  VAPID_PRIVATE = keys.privateKey;
}
try {
  webpush.setVapidDetails("mailto:admin@sparkmessenger.app", VAPID_PUBLIC, VAPID_PRIVATE);
} catch(e) {}

const userSockets = new Map(); // userId -> socketId
const activeCalls = new Map();

function getRoomId(a, b) { return [a, b].sort().join("_"); }
function authMW(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}
function safeUser(u) {
  return { id: u.id, username: u.username, phone: u.phone, avatarColor: u.avatar_color, avatarImg: u.avatar_img, status: u.status, about: u.about, language: u.language, lastSeen: u.last_seen };
}
function fmtMsg(m) {
  let reactions = {};
  try { reactions = JSON.parse(m.reactions || '{}'); } catch(e) {}
  return { id: m.id, roomId: m.room_id, fromUserId: m.from_user_id, toUserId: m.to_user_id, content: m.is_deleted ? "" : (m.content || ""), type: m.type, fileUrl: m.is_deleted ? null : m.file_url, fileName: m.file_name, fileSize: m.file_size, fileMime: m.file_mime, replyTo: m.reply_to, reactions, timestamp: m.timestamp, read: !!m.is_read, deleted: !!m.is_deleted, edited: !!m.edited };
}
function fmtGMsg(m) {
  let reactions = {};
  try { reactions = JSON.parse(m.reactions || '{}'); } catch(e) {}
  return { id: m.id, groupId: m.group_id, fromUserId: m.from_user_id, fromUsername: m.username, fromAvatarColor: m.avatar_color, content: m.is_deleted ? "" : (m.content || ""), type: m.type, fileUrl: m.is_deleted ? null : m.file_url, fileName: m.file_name, fileSize: m.file_size, fileMime: m.file_mime, replyTo: m.reply_to, reactions, timestamp: m.timestamp, deleted: !!m.is_deleted, edited: !!m.edited };
}
function getGroupFull(id) {
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(id);
  if (!g) return null;
  const members = db.prepare("SELECT gm.user_id, gm.role, u.username, u.avatar_color, u.avatar_img FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ?").all(id);
  return { id: g.id, name: g.name, adminId: g.admin_id, avatarColor: g.avatar_color, avatarImg: g.avatar_img, description: g.description, members: members.map(m => m.user_id), memberDetails: members, createdAt: g.created_at };
}
async function sendPushNotif(toUserId, title, body, data = {}) {
  try {
    const row = db.prepare("SELECT subscription FROM push_subscriptions WHERE user_id = ?").get(toUserId);
    if (!row) return;
    await webpush.sendNotification(JSON.parse(row.subscription), JSON.stringify({ title, body, data }));
  } catch(e) {}
}
function getUserSettings(userId) {
  let s = db.prepare("SELECT * FROM user_settings WHERE user_id = ?").get(userId);
  if (!s) {
    db.prepare("INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)").run(userId);
    s = db.prepare("SELECT * FROM user_settings WHERE user_id = ?").get(userId);
  }
  return s;
}

// ══════════════════════════════
// AUTH ROUTES
// ══════════════════════════════
app.post("/api/register", async (req, res) => {
  const { username, password, phone } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (username.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters" });
  if (password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
  const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (existing) return res.status(409).json({ error: "Username already taken! Please choose another." });
  if (phone) {
    const phoneExists = db.prepare("SELECT id FROM users WHERE phone = ?").get(phone);
    if (phoneExists) return res.status(409).json({ error: "Phone number already registered." });
  }
  const id = uuidv4();
  const colors = ["#25D366","#128C7E","#075E54","#34B7F1","#FF6B6B","#A29BFE","#FD79A8","#FDCB6E","#6C5CE7","#00B894"];
  const avatarColor = colors[Math.floor(Math.random() * colors.length)];
  const hashed = await bcrypt.hash(password, 10);
  db.prepare("INSERT INTO users (id, username, phone, password, avatar_color) VALUES (?, ?, ?, ?, ?)").run(id, username, phone || null, hashed, avatarColor);
  const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: safeUser(db.prepare("SELECT * FROM users WHERE id = ?").get(id)) });
});

app.post("/api/login", async (req, res) => {
  const { username, password, phone } = req.body;
  if ((!username && !phone) || !password) return res.status(400).json({ error: "Required" });
  let user;
  if (phone) {
    user = db.prepare("SELECT * FROM users WHERE phone = ?").get(phone);
  } else {
    user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  }
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: safeUser(user) });
});

app.get("/api/vapid-public-key", (req, res) => res.json({ key: VAPID_PUBLIC }));

app.post("/api/push-subscribe", authMW, (req, res) => {
  const { subscription } = req.body;
  if (!subscription) return res.status(400).json({ error: "No subscription" });
  db.prepare("INSERT OR REPLACE INTO push_subscriptions (user_id, subscription) VALUES (?, ?)").run(req.user.id, JSON.stringify(subscription));
  res.json({ ok: true });
});

app.post("/api/upload", authMW, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  res.json({ fileUrl: `/uploads/${req.file.filename}`, fileName: req.file.originalname, fileSize: req.file.size, fileMime: req.file.mimetype });
});

// ══════════════════════════════
// CONTACTS — one-way add (both see each other)
// ══════════════════════════════
app.get("/api/contacts", authMW, (req, res) => {
  const rows = db.prepare(`
    SELECT u.*, c.nickname FROM contacts c 
    JOIN users u ON u.id = c.contact_id 
    WHERE c.user_id = ?
  `).all(req.user.id);
  res.json(rows.map(u => ({ ...safeUser(u), nickname: u.nickname, online: userSockets.has(u.id) })));
});

app.post("/api/contacts/add", authMW, (req, res) => {
  const { username, phone } = req.body;
  let found;
  if (phone) {
    found = db.prepare("SELECT * FROM users WHERE phone = ?").get(phone);
  } else {
    found = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  }
  if (!found) return res.status(404).json({ error: "User not found" });
  if (found.id === req.user.id) return res.status(400).json({ error: "Cannot add yourself" });
  // Add both directions
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").run(req.user.id, found.id);
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").run(found.id, req.user.id);
  // Notify the other user
  if (userSockets.has(found.id)) {
    const me = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    io.to(`user_${found.id}`).emit("contact_added", { user: { ...safeUser(me), online: true } });
  }
  res.json({ user: { ...safeUser(found), online: userSockets.has(found.id) } });
});

app.put("/api/contacts/:id/nickname", authMW, (req, res) => {
  const { nickname } = req.body;
  db.prepare("UPDATE contacts SET nickname = ? WHERE user_id = ? AND contact_id = ?").run(nickname || '', req.user.id, req.params.id);
  res.json({ ok: true });
});

app.delete("/api/contacts/:id", authMW, (req, res) => {
  db.prepare("DELETE FROM contacts WHERE user_id = ? AND contact_id = ?").run(req.user.id, req.params.id);
  res.json({ ok: true });
});

app.post("/api/block/:id", authMW, (req, res) => { db.prepare("INSERT OR IGNORE INTO blocked (user_id, blocked_id) VALUES (?, ?)").run(req.user.id, req.params.id); res.json({ ok: true }); });
app.post("/api/unblock/:id", authMW, (req, res) => { db.prepare("DELETE FROM blocked WHERE user_id = ? AND blocked_id = ?").run(req.user.id, req.params.id); res.json({ ok: true }); });
app.get("/api/blocked", authMW, (req, res) => {
  const rows = db.prepare("SELECT u.* FROM blocked b JOIN users u ON u.id = b.blocked_id WHERE b.user_id = ?").all(req.user.id);
  res.json(rows.map(safeUser));
});

// ══════════════════════════════
// PROFILE — change username, phone, etc.
// ══════════════════════════════
app.put("/api/profile", authMW, async (req, res) => {
  const { status, about, avatarImg, language, newUsername, phone, currentPassword, newPassword } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  
  if (newUsername && newUsername !== user.username) {
    if (newUsername.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters" });
    const exists = db.prepare("SELECT id FROM users WHERE username = ? AND id != ?").get(newUsername, req.user.id);
    if (exists) return res.status(409).json({ error: "Username already taken" });
    db.prepare("UPDATE users SET username = ? WHERE id = ?").run(newUsername, req.user.id);
  }
  if (phone !== undefined) {
    if (phone) {
      const phoneExists = db.prepare("SELECT id FROM users WHERE phone = ? AND id != ?").get(phone, req.user.id);
      if (phoneExists) return res.status(409).json({ error: "Phone number already in use" });
    }
    db.prepare("UPDATE users SET phone = ? WHERE id = ?").run(phone || null, req.user.id);
  }
  if (newPassword && currentPassword) {
    if (!(await bcrypt.compare(currentPassword, user.password))) return res.status(400).json({ error: "Current password is wrong" });
    const hashed = await bcrypt.hash(newPassword, 10);
    db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashed, req.user.id);
  }
  if (status !== undefined) db.prepare("UPDATE users SET status = ? WHERE id = ?").run(status, req.user.id);
  if (about !== undefined) db.prepare("UPDATE users SET about = ? WHERE id = ?").run(about, req.user.id);
  if (avatarImg !== undefined) db.prepare("UPDATE users SET avatar_img = ? WHERE id = ?").run(avatarImg, req.user.id);
  if (language !== undefined) db.prepare("UPDATE users SET language = ? WHERE id = ?").run(language, req.user.id);
  
  const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  res.json(safeUser(updated));
});

// ══════════════════════════════
// MESSAGES with reactions, reply, edit
// ══════════════════════════════
app.get("/api/messages/:userId", authMW, (req, res) => {
  const isBlocked = db.prepare("SELECT 1 FROM blocked WHERE user_id = ? AND blocked_id = ?").get(req.user.id, req.params.userId);
  if (isBlocked) return res.json([]);
  const roomId = getRoomId(req.user.id, req.params.userId);
  res.json(db.prepare("SELECT * FROM messages WHERE room_id = ? ORDER BY timestamp ASC").all(roomId).map(fmtMsg));
});

app.delete("/api/messages/:id", authMW, (req, res) => {
  const m = db.prepare("SELECT * FROM messages WHERE id = ?").get(req.params.id);
  if (!m || m.from_user_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.prepare("UPDATE messages SET is_deleted = 1, content = '', file_url = NULL WHERE id = ?").run(req.params.id);
  io.to(`user_${m.to_user_id}`).emit("message_deleted", { messageId: req.params.id });
  io.to(`user_${m.from_user_id}`).emit("message_deleted", { messageId: req.params.id });
  res.json({ ok: true });
});

// Search messages
app.get("/api/messages/:userId/search", authMW, (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);
  const roomId = getRoomId(req.user.id, req.params.userId);
  res.json(db.prepare("SELECT * FROM messages WHERE room_id = ? AND content LIKE ? AND is_deleted = 0 ORDER BY timestamp ASC").all(roomId, `%${q}%`).map(fmtMsg));
});

// ══════════════════════════════
// PIN / ARCHIVE / META
// ══════════════════════════════
app.post("/api/pin/:chatId", authMW, (req, res) => { db.prepare("INSERT OR IGNORE INTO pinned_chats (user_id, chat_id) VALUES (?, ?)").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.post("/api/unpin/:chatId", authMW, (req, res) => { db.prepare("DELETE FROM pinned_chats WHERE user_id = ? AND chat_id = ?").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.post("/api/archive/:chatId", authMW, (req, res) => { db.prepare("INSERT OR IGNORE INTO archived_chats (user_id, chat_id) VALUES (?, ?)").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.post("/api/unarchive/:chatId", authMW, (req, res) => { db.prepare("DELETE FROM archived_chats WHERE user_id = ? AND chat_id = ?").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.get("/api/meta", authMW, (req, res) => {
  res.json({
    pinned: db.prepare("SELECT chat_id FROM pinned_chats WHERE user_id = ?").all(req.user.id).map(r => r.chat_id),
    archived: db.prepare("SELECT chat_id FROM archived_chats WHERE user_id = ?").all(req.user.id).map(r => r.chat_id)
  });
});

// ══════════════════════════════
// USER SETTINGS
// ══════════════════════════════
app.get("/api/settings", authMW, (req, res) => res.json(getUserSettings(req.user.id)));
app.put("/api/settings", authMW, (req, res) => {
  const s = req.body;
  db.prepare("INSERT OR REPLACE INTO user_settings (user_id, notification_sound, notification_vibrate, read_receipts, last_seen_visible, wallpaper, font_size, enter_to_send) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(
    req.user.id,
    s.notification_sound ?? 1, s.notification_vibrate ?? 1,
    s.read_receipts ?? 1, s.last_seen_visible ?? 1,
    s.wallpaper ?? '', s.font_size ?? 'medium', s.enter_to_send ?? 1
  );
  res.json({ ok: true });
});

// ══════════════════════════════
// STATUSES with views & caption
// ══════════════════════════════
app.get("/api/statuses", authMW, (req, res) => {
  const contactIds = db.prepare("SELECT contact_id FROM contacts WHERE user_id = ?").all(req.user.id).map(r => r.contact_id);
  const allIds = [req.user.id, ...contactIds];
  const cutoff = Date.now() - 86400000;
  const result = allIds.map(uid => {
    const u = db.prepare("SELECT * FROM users WHERE id = ?").get(uid);
    if (!u) return null;
    const sts = db.prepare("SELECT * FROM statuses WHERE user_id = ? AND timestamp > ? ORDER BY timestamp ASC").all(uid, cutoff);
    return { user: safeUser(u), statuses: sts.map(s => ({...s, views: JSON.parse(s.views||'[]')})), isMe: uid === req.user.id };
  }).filter(Boolean);
  res.json(result);
});

app.post("/api/status", authMW, (req, res) => {
  const { content, type, caption } = req.body;
  const id = uuidv4();
  db.prepare("INSERT INTO statuses (id, user_id, content, type, caption) VALUES (?, ?, ?, ?, ?)").run(id, req.user.id, content, type || "text", caption || "");
  io.emit("new_status", { userId: req.user.id });
  res.json({ id, content, type, caption, timestamp: Date.now() });
});

app.post("/api/status/:id/view", authMW, (req, res) => {
  const st = db.prepare("SELECT * FROM statuses WHERE id = ?").get(req.params.id);
  if (!st) return res.status(404).json({ error: "Not found" });
  let views = [];
  try { views = JSON.parse(st.views || '[]'); } catch(e) {}
  if (!views.includes(req.user.id)) {
    views.push(req.user.id);
    db.prepare("UPDATE statuses SET views = ? WHERE id = ?").run(JSON.stringify(views), req.params.id);
  }
  res.json({ ok: true });
});

app.delete("/api/status/:id", authMW, (req, res) => {
  db.prepare("DELETE FROM statuses WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ══════════════════════════════
// GROUPS
// ══════════════════════════════
app.post("/api/groups", authMW, (req, res) => {
  const { name, memberIds } = req.body;
  if (!name || !memberIds?.length) return res.status(400).json({ error: "Required" });
  const id = uuidv4();
  db.prepare("INSERT INTO groups (id, name, admin_id) VALUES (?, ?, ?)").run(id, name, req.user.id);
  for (const mId of [req.user.id, ...memberIds]) {
    const role = mId === req.user.id ? 'admin' : 'member';
    db.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)").run(id, mId, role);
  }
  const group = getGroupFull(id);
  group.members.forEach(mId => { if (userSockets.has(mId)) io.to(`user_${mId}`).emit("added_to_group", group); });
  res.json(group);
});

app.get("/api/groups", authMW, (req, res) => {
  const ids = db.prepare("SELECT group_id FROM group_members WHERE user_id = ?").all(req.user.id).map(r => r.group_id);
  res.json(ids.map(getGroupFull).filter(Boolean));
});

app.get("/api/groups/:id/messages", authMW, (req, res) => {
  if (!db.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").get(req.params.id, req.user.id)) return res.status(403).json({ error: "Forbidden" });
  const msgs = db.prepare("SELECT gm.*, u.username, u.avatar_color FROM group_messages gm JOIN users u ON u.id = gm.from_user_id WHERE gm.group_id = ? ORDER BY gm.timestamp ASC").all(req.params.id);
  res.json(msgs.map(fmtGMsg));
});

app.post("/api/groups/:id/leave", authMW, (req, res) => {
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });
  db.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").run(req.params.id, req.user.id);
  const remaining = db.prepare("SELECT user_id FROM group_members WHERE group_id = ?").all(req.params.id);
  if (!remaining.length) db.prepare("DELETE FROM groups WHERE id = ?").run(req.params.id);
  else if (g.admin_id === req.user.id) db.prepare("UPDATE groups SET admin_id = ? WHERE id = ?").run(remaining[0].user_id, req.params.id);
  const updated = getGroupFull(req.params.id);
  if (updated) io.emit("group_updated", updated);
  res.json({ ok: true });
});

app.put("/api/groups/:id", authMW, (req, res) => {
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(req.params.id);
  if (!g || g.admin_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  const { name, description, avatarImg } = req.body;
  if (name) db.prepare("UPDATE groups SET name = ? WHERE id = ?").run(name, req.params.id);
  if (description !== undefined) db.prepare("UPDATE groups SET description = ? WHERE id = ?").run(description, req.params.id);
  if (avatarImg !== undefined) db.prepare("UPDATE groups SET avatar_img = ? WHERE id = ?").run(avatarImg, req.params.id);
  const updated = getGroupFull(req.params.id);
  io.emit("group_updated", updated);
  res.json(updated);
});

app.post("/api/groups/:id/add-member", authMW, (req, res) => {
  const { userId } = req.body;
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(req.params.id);
  if (!g || g.admin_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, 'member')").run(req.params.id, userId);
  const group = getGroupFull(req.params.id);
  io.to(`user_${userId}`).emit("added_to_group", group);
  if (userSockets.has(userId)) io.to(`user_${userId}`).emit("added_to_group", group);
  io.emit("group_updated", group);
  res.json(group);
});

app.post("/api/groups/:id/remove-member", authMW, (req, res) => {
  const { userId } = req.body;
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(req.params.id);
  if (!g || g.admin_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").run(req.params.id, userId);
  const group = getGroupFull(req.params.id);
  io.emit("group_updated", group);
  io.to(`user_${userId}`).emit("removed_from_group", { groupId: req.params.id });
  res.json(group);
});

// ══════════════════════════════
// POLLS
// ══════════════════════════════
app.post("/api/polls", authMW, (req, res) => {
  const { question, options, groupId, roomId } = req.body;
  if (!question || !options?.length) return res.status(400).json({ error: "Required" });
  const id = uuidv4();
  db.prepare("INSERT INTO polls (id, creator_id, question, options, group_id, room_id) VALUES (?, ?, ?, ?, ?, ?)").run(id, req.user.id, question, JSON.stringify(options), groupId || null, roomId || null);
  res.json({ id, question, options, votes: {}, creatorId: req.user.id });
});

app.post("/api/polls/:id/vote", authMW, (req, res) => {
  const { option } = req.body;
  const poll = db.prepare("SELECT * FROM polls WHERE id = ?").get(req.params.id);
  if (!poll) return res.status(404).json({ error: "Not found" });
  let votes = {};
  try { votes = JSON.parse(poll.votes); } catch(e) {}
  votes[req.user.id] = option;
  db.prepare("UPDATE polls SET votes = ? WHERE id = ?").run(JSON.stringify(votes), req.params.id);
  const result = { ...poll, votes };
  if (poll.group_id) io.to(`group_${poll.group_id}`).emit("poll_updated", result);
  res.json(result);
});

app.get("/api/polls/:id", authMW, (req, res) => {
  const poll = db.prepare("SELECT * FROM polls WHERE id = ?").get(req.params.id);
  if (!poll) return res.status(404).json({ error: "Not found" });
  res.json({ ...poll, options: JSON.parse(poll.options), votes: JSON.parse(poll.votes) });
});

// ══════════════════════════════
// USER SEARCH (for adding contacts)
// ══════════════════════════════
app.get("/api/users/search", authMW, (req, res) => {
  const q = req.query.q;
  if (!q || q.length < 2) return res.json([]);
  const rows = db.prepare("SELECT * FROM users WHERE (username LIKE ? OR phone LIKE ?) AND id != ? LIMIT 10").all(`%${q}%`, `%${q}%`, req.user.id);
  res.json(rows.map(u => ({ ...safeUser(u), online: userSockets.has(u.id) })));
});

// Drafts
app.post("/api/drafts", authMW, (req, res) => {
  const { chatId, content } = req.body;
  db.prepare("INSERT OR REPLACE INTO message_drafts (user_id, chat_id, content) VALUES (?, ?, ?)").run(req.user.id, chatId, content || '');
  res.json({ ok: true });
});
app.get("/api/drafts", authMW, (req, res) => {
  const drafts = db.prepare("SELECT * FROM message_drafts WHERE user_id = ?").all(req.user.id);
  res.json(drafts);
});

// Get user info by id
app.get("/api/users/:id", authMW, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!u) return res.status(404).json({ error: "Not found" });
  res.json({ ...safeUser(u), online: userSockets.has(u.id) });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ══════════════════════════════
// SOCKET.IO
// ══════════════════════════════
io.on("connection", (socket) => {
  socket.on("authenticate", (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.id;
      userSockets.set(decoded.id, socket.id);
      socket.join(`user_${decoded.id}`);
      db.prepare("SELECT group_id FROM group_members WHERE user_id = ?").all(decoded.id).forEach(({ group_id }) => socket.join(`group_${group_id}`));
      db.prepare("UPDATE users SET is_online = 1 WHERE id = ?").run(decoded.id);
      io.emit("user_online", { userId: decoded.id });
      socket.emit("authenticated", { userId: decoded.id });
    } catch { socket.emit("auth_error"); }
  });

  socket.on("send_message", ({ toUserId, content, type, fileUrl, fileName, fileSize, fileMime, replyTo }) => {
    if (!socket.userId) return;
    if (db.prepare("SELECT 1 FROM blocked WHERE user_id = ? AND blocked_id = ?").get(toUserId, socket.userId)) return;
    const roomId = getRoomId(socket.userId, toUserId);
    const id = uuidv4(), timestamp = Date.now();
    db.prepare("INSERT INTO messages (id, room_id, from_user_id, to_user_id, content, type, file_url, file_name, file_size, file_mime, reply_to, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, roomId, socket.userId, toUserId, content || "", type || "text", fileUrl || null, fileName || null, fileSize || null, fileMime || null, replyTo || null, timestamp);
    const msg = { id, roomId, fromUserId: socket.userId, toUserId, content: content || "", type: type || "text", fileUrl: fileUrl || null, fileName: fileName || null, fileSize: fileSize || null, fileMime: fileMime || null, replyTo: replyTo || null, reactions: {}, timestamp, read: false, deleted: false };
    io.to(`user_${toUserId}`).emit("new_message", msg);
    socket.emit("message_sent", msg);
    // Push notification
    if (!userSockets.has(toUserId)) {
      const sender = db.prepare("SELECT username FROM users WHERE id = ?").get(socket.userId);
      sendPushNotif(toUserId, `📩 ${sender?.username || "New Message"}`, type === "text" ? (content || "") : `Sent a ${type}`, { type: "message", fromUserId: socket.userId });
    }
  });

  socket.on("send_group_message", ({ groupId, content, type, fileUrl, fileName, fileSize, fileMime, replyTo }) => {
    if (!socket.userId) return;
    if (!db.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").get(groupId, socket.userId)) return;
    const sender = db.prepare("SELECT * FROM users WHERE id = ?").get(socket.userId);
    const id = uuidv4(), timestamp = Date.now();
    db.prepare("INSERT INTO group_messages (id, group_id, from_user_id, content, type, file_url, file_name, file_size, file_mime, reply_to, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, groupId, socket.userId, content || "", type || "text", fileUrl || null, fileName || null, fileSize || null, fileMime || null, replyTo || null, timestamp);
    const msg = { id, groupId, fromUserId: socket.userId, fromUsername: sender?.username, fromAvatarColor: sender?.avatar_color, content: content || "", type: type || "text", fileUrl: fileUrl || null, fileName: fileName || null, fileSize: fileSize || null, fileMime: fileMime || null, replyTo: replyTo || null, reactions: {}, timestamp, deleted: false };
    io.to(`group_${groupId}`).emit("new_group_message", msg);
    // Push to offline members
    const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(groupId);
    const members = db.prepare("SELECT user_id FROM group_members WHERE group_id = ?").all(groupId);
    members.forEach(({ user_id }) => {
      if (user_id !== socket.userId && !userSockets.has(user_id)) {
        sendPushNotif(user_id, `📩 ${g?.name || "Group"}: ${sender?.username}`, type === "text" ? (content || "") : `Sent a ${type}`, { type: "group_message", groupId });
      }
    });
  });

  socket.on("edit_message", ({ messageId, newContent, toUserId }) => {
    if (!socket.userId) return;
    const m = db.prepare("SELECT * FROM messages WHERE id = ? AND from_user_id = ?").get(messageId, socket.userId);
    if (!m) return;
    db.prepare("UPDATE messages SET content = ?, edited = 1 WHERE id = ?").run(newContent, messageId);
    const upd = { messageId, newContent, edited: true };
    io.to(`user_${toUserId}`).emit("message_edited", upd);
    socket.emit("message_edited", upd);
  });

  socket.on("react_message", ({ messageId, emoji, toUserId, isGroup, groupId }) => {
    if (!socket.userId) return;
    if (isGroup) {
      const m = db.prepare("SELECT * FROM group_messages WHERE id = ?").get(messageId);
      if (!m) return;
      let reactions = {};
      try { reactions = JSON.parse(m.reactions || '{}'); } catch(e) {}
      if (!reactions[emoji]) reactions[emoji] = [];
      const idx = reactions[emoji].indexOf(socket.userId);
      if (idx >= 0) reactions[emoji].splice(idx, 1);
      else reactions[emoji].push(socket.userId);
      if (!reactions[emoji].length) delete reactions[emoji];
      db.prepare("UPDATE group_messages SET reactions = ? WHERE id = ?").run(JSON.stringify(reactions), messageId);
      io.to(`group_${groupId}`).emit("message_reacted", { messageId, reactions, isGroup: true, groupId });
    } else {
      const m = db.prepare("SELECT * FROM messages WHERE id = ?").get(messageId);
      if (!m) return;
      let reactions = {};
      try { reactions = JSON.parse(m.reactions || '{}'); } catch(e) {}
      if (!reactions[emoji]) reactions[emoji] = [];
      const idx = reactions[emoji].indexOf(socket.userId);
      if (idx >= 0) reactions[emoji].splice(idx, 1);
      else reactions[emoji].push(socket.userId);
      if (!reactions[emoji].length) delete reactions[emoji];
      db.prepare("UPDATE messages SET reactions = ? WHERE id = ?").run(JSON.stringify(reactions), messageId);
      const upd = { messageId, reactions };
      io.to(`user_${toUserId}`).emit("message_reacted", upd);
      socket.emit("message_reacted", upd);
    }
  });

  socket.on("mark_read", ({ fromUserId }) => {
    if (!socket.userId) return;
    db.prepare("UPDATE messages SET is_read = 1 WHERE room_id = ? AND to_user_id = ?").run(getRoomId(socket.userId, fromUserId), socket.userId);
    io.to(`user_${fromUserId}`).emit("messages_read", { byUserId: socket.userId });
  });

  socket.on("typing_start", ({ toUserId }) => io.to(`user_${toUserId}`).emit("user_typing", { userId: socket.userId }));
  socket.on("typing_stop", ({ toUserId }) => io.to(`user_${toUserId}`).emit("user_stop_typing", { userId: socket.userId }));
  socket.on("group_typing_start", ({ groupId }) => socket.to(`group_${groupId}`).emit("group_user_typing", { userId: socket.userId, groupId }));
  socket.on("group_typing_stop", ({ groupId }) => socket.to(`group_${groupId}`).emit("group_user_stop_typing", { userId: socket.userId, groupId }));

  socket.on("delete_message", ({ messageId, toUserId }) => {
    if (!socket.userId) return;
    if (db.prepare("SELECT id FROM messages WHERE id = ? AND from_user_id = ?").get(messageId, socket.userId)) {
      db.prepare("UPDATE messages SET is_deleted = 1, content = '', file_url = NULL WHERE id = ?").run(messageId);
    }
    io.to(`user_${toUserId}`).emit("message_deleted", { messageId });
    socket.emit("message_deleted", { messageId });
  });

  socket.on("delete_group_message", ({ messageId, groupId }) => {
    if (!socket.userId) return;
    const m = db.prepare("SELECT * FROM group_messages WHERE id = ? AND from_user_id = ?").get(messageId, socket.userId);
    if (!m) return;
    db.prepare("UPDATE group_messages SET is_deleted = 1, content = '', file_url = NULL WHERE id = ?").run(messageId);
    io.to(`group_${groupId}`).emit("message_deleted", { messageId, groupId, isGroup: true });
  });

  // Calls with push notification for incoming call
  socket.on("call_user", ({ toUserId, offer, callId, callType }) => {
    const caller = db.prepare("SELECT * FROM users WHERE id = ?").get(socket.userId);
    const cId = callId || uuidv4();
    activeCalls.set(cId, { id: cId, callerId: socket.userId, calleeId: toUserId, status: "ringing", type: callType || "voice" });
    const callData = { callId: cId, fromUserId: socket.userId, fromUsername: caller?.username, fromAvatarColor: caller?.avatar_color, fromAvatarImg: caller?.avatar_img, offer, callType: callType || "voice" };
    io.to(`user_${toUserId}`).emit("incoming_call", callData);
    socket.emit("call_initiated", { callId: cId });
    // Push notification for call
    if (!userSockets.has(toUserId)) {
      sendPushNotif(toUserId, `📞 ${caller?.username || "Unknown"}`, callType === "video" ? "Incoming video call" : "Incoming voice call", { type: "call", callType, fromUserId: socket.userId });
    }
  });

  socket.on("answer_call", ({ callId, toUserId, answer }) => {
    const call = activeCalls.get(callId);
    if (call) call.status = "active";
    io.to(`user_${toUserId}`).emit("call_answered", { callId, answer });
  });
  socket.on("reject_call", ({ callId, toUserId }) => { activeCalls.delete(callId); io.to(`user_${toUserId}`).emit("call_rejected", { callId }); });
  socket.on("end_call", ({ callId, toUserId }) => { activeCalls.delete(callId); io.to(`user_${toUserId}`).emit("call_ended", { callId }); });
  socket.on("ice_candidate", ({ toUserId, candidate, callId }) => { io.to(`user_${toUserId}`).emit("ice_candidate", { candidate, callId, fromUserId: socket.userId }); });

  // Presence
  socket.on("set_presence", ({ status }) => {
    if (!socket.userId) return;
    io.emit("user_presence", { userId: socket.userId, status });
  });

  socket.on("disconnect", () => {
    if (socket.userId) {
      userSockets.delete(socket.userId);
      db.prepare("UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?").run(Date.now(), socket.userId);
      io.emit("user_offline", { userId: socket.userId, lastSeen: Date.now() });
    }
  });
});

// Scheduled message processor
setInterval(() => {
  const now = Date.now();
  const due = db.prepare("SELECT * FROM scheduled_messages WHERE send_at <= ? AND sent = 0").all(now);
  due.forEach(sm => {
    db.prepare("UPDATE scheduled_messages SET sent = 1 WHERE id = ?").run(sm.id);
    if (sm.to_user_id) {
      const id = uuidv4();
      db.prepare("INSERT INTO messages (id, room_id, from_user_id, to_user_id, content, type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, getRoomId(sm.from_user_id, sm.to_user_id), sm.from_user_id, sm.to_user_id, sm.content, sm.type, now);
      const msg = { id, fromUserId: sm.from_user_id, toUserId: sm.to_user_id, content: sm.content, type: sm.type, timestamp: now, read: false, deleted: false };
      io.to(`user_${sm.to_user_id}`).emit("new_message", msg);
      io.to(`user_${sm.from_user_id}`).emit("message_sent", msg);
    }
  });
}, 30000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Spark Messenger v5 running on port ${PORT}`));
