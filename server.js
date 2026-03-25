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
    bio TEXT DEFAULT '',
    location TEXT DEFAULT '',
    website TEXT DEFAULT '',
    last_seen INTEGER DEFAULT (strftime('%s','now') * 1000),
    is_online INTEGER DEFAULT 0,
    notifications_enabled INTEGER DEFAULT 1,
    read_receipts INTEGER DEFAULT 1,
    show_online INTEGER DEFAULT 1,
    wallpaper TEXT DEFAULT '',
    font_size TEXT DEFAULT 'medium',
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
    reply_to TEXT DEFAULT NULL,
    forwarded_from TEXT DEFAULT NULL,
    reactions TEXT DEFAULT '{}',
    timestamp INTEGER DEFAULT (strftime('%s','now') * 1000),
    edited_at INTEGER DEFAULT NULL,
    is_read INTEGER DEFAULT 0,
    is_deleted INTEGER DEFAULT 0,
    is_starred INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id);
  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, admin_id TEXT NOT NULL,
    avatar_color TEXT DEFAULT '#25D366', avatar_img TEXT,
    description TEXT DEFAULT '',
    invite_link TEXT DEFAULT '',
    is_muted INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL, user_id TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at INTEGER DEFAULT (strftime('%s','now') * 1000),
    PRIMARY KEY (group_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS group_messages (
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL, from_user_id TEXT NOT NULL,
    content TEXT DEFAULT '', type TEXT DEFAULT 'text',
    file_url TEXT, file_name TEXT, file_size INTEGER, file_mime TEXT,
    reply_to TEXT DEFAULT NULL,
    reactions TEXT DEFAULT '{}',
    timestamp INTEGER DEFAULT (strftime('%s','now') * 1000),
    edited_at INTEGER DEFAULT NULL,
    is_deleted INTEGER DEFAULT 0,
    is_starred INTEGER DEFAULT 0
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
  CREATE TABLE IF NOT EXISTS muted_chats (
    user_id TEXT NOT NULL, chat_id TEXT NOT NULL, until INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, chat_id)
  );
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    user_id TEXT PRIMARY KEY, subscription TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS starred_messages (
    user_id TEXT NOT NULL, message_id TEXT NOT NULL,
    PRIMARY KEY (user_id, message_id)
  );
  CREATE TABLE IF NOT EXISTS polls (
    id TEXT PRIMARY KEY, room_id TEXT NOT NULL, creator_id TEXT NOT NULL,
    question TEXT NOT NULL, options TEXT NOT NULL,
    votes TEXT DEFAULT '{}',
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS call_logs (
    id TEXT PRIMARY KEY, caller_id TEXT NOT NULL, callee_id TEXT NOT NULL,
    call_type TEXT DEFAULT 'voice', status TEXT DEFAULT 'missed',
    duration INTEGER DEFAULT 0,
    timestamp INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp INTEGER DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS scheduled_messages (
    id TEXT PRIMARY KEY, from_user_id TEXT NOT NULL, to_user_id TEXT,
    group_id TEXT, content TEXT NOT NULL, type TEXT DEFAULT 'text',
    scheduled_at INTEGER NOT NULL, sent INTEGER DEFAULT 0
  );
`);

// Add columns if they don't exist (migration)
const tryAddCol = (table, col, def) => {
  try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`); } catch(e) {}
};
tryAddCol('users', 'phone', 'TEXT');
tryAddCol('users', 'bio', 'TEXT DEFAULT ""');
tryAddCol('users', 'location', 'TEXT DEFAULT ""');
tryAddCol('users', 'website', 'TEXT DEFAULT ""');
tryAddCol('users', 'last_seen', 'INTEGER DEFAULT 0');
tryAddCol('users', 'is_online', 'INTEGER DEFAULT 0');
tryAddCol('users', 'notifications_enabled', 'INTEGER DEFAULT 1');
tryAddCol('users', 'read_receipts', 'INTEGER DEFAULT 1');
tryAddCol('users', 'show_online', 'INTEGER DEFAULT 1');
tryAddCol('users', 'wallpaper', 'TEXT DEFAULT ""');
tryAddCol('users', 'font_size', 'TEXT DEFAULT "medium"');
tryAddCol('messages', 'reply_to', 'TEXT DEFAULT NULL');
tryAddCol('messages', 'forwarded_from', 'TEXT DEFAULT NULL');
tryAddCol('messages', 'reactions', 'TEXT DEFAULT "{}"');
tryAddCol('messages', 'edited_at', 'INTEGER DEFAULT NULL');
tryAddCol('messages', 'is_starred', 'INTEGER DEFAULT 0');
tryAddCol('group_messages', 'reply_to', 'TEXT DEFAULT NULL');
tryAddCol('group_messages', 'reactions', 'TEXT DEFAULT "{}"');
tryAddCol('group_messages', 'edited_at', 'INTEGER DEFAULT NULL');
tryAddCol('group_messages', 'is_starred', 'INTEGER DEFAULT 0');
tryAddCol('contacts', 'nickname', 'TEXT DEFAULT ""');
tryAddCol('statuses', 'caption', 'TEXT DEFAULT ""');
tryAddCol('statuses', 'views', 'TEXT DEFAULT "[]"');
tryAddCol('groups', 'invite_link', 'TEXT DEFAULT ""');

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

const userSockets = new Map();
const activeCalls = new Map();

function getRoomId(a, b) { return [a, b].sort().join("_"); }
function authMW(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}
function safeUser(u) {
  return {
    id: u.id, username: u.username, phone: u.phone || null,
    avatarColor: u.avatar_color, avatarImg: u.avatar_img,
    status: u.status, about: u.about, language: u.language,
    bio: u.bio || '', location: u.location || '', website: u.website || '',
    lastSeen: u.last_seen || 0, isOnline: !!u.is_online,
    readReceipts: u.read_receipts !== undefined ? !!u.read_receipts : true,
    showOnline: u.show_online !== undefined ? !!u.show_online : true,
    wallpaper: u.wallpaper || '', fontSize: u.font_size || 'medium'
  };
}
function fmtMsg(m) {
  return {
    id: m.id, roomId: m.room_id, fromUserId: m.from_user_id, toUserId: m.to_user_id,
    content: m.is_deleted ? "" : (m.content || ""), type: m.type,
    fileUrl: m.is_deleted ? null : m.file_url, fileName: m.file_name,
    fileSize: m.file_size, fileMime: m.file_mime,
    replyTo: m.reply_to || null, forwardedFrom: m.forwarded_from || null,
    reactions: JSON.parse(m.reactions || '{}'),
    timestamp: m.timestamp, editedAt: m.edited_at || null,
    read: !!m.is_read, deleted: !!m.is_deleted, starred: !!m.is_starred
  };
}
function fmtGMsg(m) {
  return {
    id: m.id, groupId: m.group_id, fromUserId: m.from_user_id,
    fromUsername: m.username, fromAvatarColor: m.avatar_color,
    content: m.is_deleted ? "" : (m.content || ""), type: m.type,
    fileUrl: m.is_deleted ? null : m.file_url, fileName: m.file_name,
    fileSize: m.file_size, fileMime: m.file_mime,
    replyTo: m.reply_to || null,
    reactions: JSON.parse(m.reactions || '{}'),
    timestamp: m.timestamp, editedAt: m.edited_at || null,
    deleted: !!m.is_deleted, starred: !!m.is_starred
  };
}
function getGroupFull(id) {
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(id);
  if (!g) return null;
  const members = db.prepare("SELECT gm.user_id, gm.role, u.username, u.avatar_color, u.avatar_img FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ?").all(id);
  return {
    id: g.id, name: g.name, adminId: g.admin_id,
    avatarColor: g.avatar_color, avatarImg: g.avatar_img,
    description: g.description, inviteLink: g.invite_link || '',
    members: members.map(m => m.user_id),
    membersInfo: members,
    createdAt: g.created_at
  };
}
async function sendPushNotif(toUserId, title, body, data = {}) {
  try {
    const row = db.prepare("SELECT subscription FROM push_subscriptions WHERE user_id = ?").get(toUserId);
    if (!row) return;
    await webpush.sendNotification(JSON.parse(row.subscription), JSON.stringify({ title, body, data }));
  } catch(e) {}
}

// ══════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════
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

// ══════════════════════════════════════════
// CONTACTS - Updated: one-sided add
// ══════════════════════════════════════════
app.get("/api/contacts", authMW, (req, res) => {
  const rows = db.prepare("SELECT u.*, c.nickname FROM contacts c JOIN users u ON u.id = c.contact_id WHERE c.user_id = ?").all(req.user.id);
  res.json(rows.map(u => ({ ...safeUser(u), online: userSockets.has(u.id), nickname: u.nickname || '' })));
});

app.post("/api/contacts/add", authMW, (req, res) => {
  const { username, phone } = req.body;
  let found;
  if (phone) {
    found = db.prepare("SELECT * FROM users WHERE phone = ?").get(phone);
  } else if (username) {
    found = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  }
  if (!found) return res.status(404).json({ error: "User not found" });
  if (found.id === req.user.id) return res.status(400).json({ error: "Cannot add yourself" });
  // One-sided add - both see each other
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").run(req.user.id, found.id);
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").run(found.id, req.user.id);
  // Notify the other user
  if (userSockets.has(found.id)) {
    const me = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    io.to(`user_${found.id}`).emit("contact_added", { user: { ...safeUser(me), online: true } });
  }
  res.json({ user: { ...safeUser(found), online: userSockets.has(found.id), nickname: '' } });
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

// ══════════════════════════════════════════
// PROFILE - with username change
// ══════════════════════════════════════════
app.put("/api/profile", authMW, async (req, res) => {
  const { status, about, avatarImg, language, username, bio, location, website,
          notificationsEnabled, readReceipts, showOnline, wallpaper, fontSize, phone, password, newPassword } = req.body;
  
  // Username change
  if (username && username !== req.user.username) {
    if (username.length < 3) return res.status(400).json({ error: "Username too short" });
    const exists = db.prepare("SELECT id FROM users WHERE username = ? AND id != ?").get(username, req.user.id);
    if (exists) return res.status(409).json({ error: "Username already taken" });
    db.prepare("UPDATE users SET username = ? WHERE id = ?").run(username, req.user.id);
  }
  
  // Password change
  if (password && newPassword) {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Current password is incorrect" });
    const hashed = await bcrypt.hash(newPassword, 10);
    db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashed, req.user.id);
  }

  if (status !== undefined) db.prepare("UPDATE users SET status = ? WHERE id = ?").run(status, req.user.id);
  if (about !== undefined) db.prepare("UPDATE users SET about = ? WHERE id = ?").run(about, req.user.id);
  if (avatarImg !== undefined) db.prepare("UPDATE users SET avatar_img = ? WHERE id = ?").run(avatarImg, req.user.id);
  if (language !== undefined) db.prepare("UPDATE users SET language = ? WHERE id = ?").run(language, req.user.id);
  if (bio !== undefined) db.prepare("UPDATE users SET bio = ? WHERE id = ?").run(bio, req.user.id);
  if (location !== undefined) db.prepare("UPDATE users SET location = ? WHERE id = ?").run(location, req.user.id);
  if (website !== undefined) db.prepare("UPDATE users SET website = ? WHERE id = ?").run(website, req.user.id);
  if (phone !== undefined) db.prepare("UPDATE users SET phone = ? WHERE id = ?").run(phone || null, req.user.id);
  if (notificationsEnabled !== undefined) db.prepare("UPDATE users SET notifications_enabled = ? WHERE id = ?").run(notificationsEnabled ? 1 : 0, req.user.id);
  if (readReceipts !== undefined) db.prepare("UPDATE users SET read_receipts = ? WHERE id = ?").run(readReceipts ? 1 : 0, req.user.id);
  if (showOnline !== undefined) db.prepare("UPDATE users SET show_online = ? WHERE id = ?").run(showOnline ? 1 : 0, req.user.id);
  if (wallpaper !== undefined) db.prepare("UPDATE users SET wallpaper = ? WHERE id = ?").run(wallpaper, req.user.id);
  if (fontSize !== undefined) db.prepare("UPDATE users SET font_size = ? WHERE id = ?").run(fontSize, req.user.id);

  const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  // Notify contacts of profile change
  io.emit("profile_updated", safeUser(updated));
  res.json(safeUser(updated));
});

// ══════════════════════════════════════════
// MESSAGES
// ══════════════════════════════════════════
app.get("/api/messages/:userId", authMW, (req, res) => {
  const isBlocked = db.prepare("SELECT 1 FROM blocked WHERE user_id = ? AND blocked_id = ?").get(req.user.id, req.params.userId);
  if (isBlocked) return res.json([]);
  const roomId = getRoomId(req.user.id, req.params.userId);
  res.json(db.prepare("SELECT * FROM messages WHERE room_id = ? ORDER BY timestamp ASC").all(roomId).map(fmtMsg));
});

// Edit message
app.put("/api/messages/:id", authMW, (req, res) => {
  const { content } = req.body;
  const msg = db.prepare("SELECT * FROM messages WHERE id = ? AND from_user_id = ?").get(req.params.id, req.user.id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  const now = Date.now();
  db.prepare("UPDATE messages SET content = ?, edited_at = ? WHERE id = ?").run(content, now, req.params.id);
  io.to(`user_${msg.to_user_id}`).emit("message_edited", { messageId: req.params.id, content, editedAt: now });
  io.to(`user_${req.user.id}`).emit("message_edited", { messageId: req.params.id, content, editedAt: now });
  res.json({ ok: true });
});

// React to message
app.post("/api/messages/:id/react", authMW, (req, res) => {
  const { emoji } = req.body;
  const msg = db.prepare("SELECT * FROM messages WHERE id = ?").get(req.params.id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  const reactions = JSON.parse(msg.reactions || '{}');
  if (!reactions[emoji]) reactions[emoji] = [];
  const idx = reactions[emoji].indexOf(req.user.id);
  if (idx >= 0) reactions[emoji].splice(idx, 1);
  else reactions[emoji].push(req.user.id);
  if (!reactions[emoji].length) delete reactions[emoji];
  db.prepare("UPDATE messages SET reactions = ? WHERE id = ?").run(JSON.stringify(reactions), req.params.id);
  const roomId = msg.room_id;
  io.to(`user_${msg.from_user_id}`).emit("message_reaction", { messageId: req.params.id, reactions });
  io.to(`user_${msg.to_user_id}`).emit("message_reaction", { messageId: req.params.id, reactions });
  res.json({ ok: true });
});

// Star message
app.post("/api/messages/:id/star", authMW, (req, res) => {
  const existing = db.prepare("SELECT 1 FROM starred_messages WHERE user_id = ? AND message_id = ?").get(req.user.id, req.params.id);
  if (existing) {
    db.prepare("DELETE FROM starred_messages WHERE user_id = ? AND message_id = ?").run(req.user.id, req.params.id);
    res.json({ starred: false });
  } else {
    db.prepare("INSERT OR IGNORE INTO starred_messages (user_id, message_id) VALUES (?, ?)").run(req.user.id, req.params.id);
    res.json({ starred: true });
  }
});

app.get("/api/starred", authMW, (req, res) => {
  const ids = db.prepare("SELECT message_id FROM starred_messages WHERE user_id = ?").all(req.user.id).map(r => r.message_id);
  if (!ids.length) return res.json([]);
  const msgs = db.prepare(`SELECT * FROM messages WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY timestamp DESC`).all(...ids);
  res.json(msgs.map(fmtMsg));
});

app.post("/api/pin/:chatId", authMW, (req, res) => { db.prepare("INSERT OR IGNORE INTO pinned_chats (user_id, chat_id) VALUES (?, ?)").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.post("/api/unpin/:chatId", authMW, (req, res) => { db.prepare("DELETE FROM pinned_chats WHERE user_id = ? AND chat_id = ?").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.post("/api/archive/:chatId", authMW, (req, res) => { db.prepare("INSERT OR IGNORE INTO archived_chats (user_id, chat_id) VALUES (?, ?)").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.post("/api/unarchive/:chatId", authMW, (req, res) => { db.prepare("DELETE FROM archived_chats WHERE user_id = ? AND chat_id = ?").run(req.user.id, req.params.chatId); res.json({ ok: true }); });
app.post("/api/mute/:chatId", authMW, (req, res) => {
  const { until } = req.body;
  db.prepare("INSERT OR REPLACE INTO muted_chats (user_id, chat_id, until) VALUES (?, ?, ?)").run(req.user.id, req.params.chatId, until || 0);
  res.json({ ok: true });
});
app.post("/api/unmute/:chatId", authMW, (req, res) => { db.prepare("DELETE FROM muted_chats WHERE user_id = ? AND chat_id = ?").run(req.user.id, req.params.chatId); res.json({ ok: true }); });

app.get("/api/meta", authMW, (req, res) => {
  res.json({
    pinned: db.prepare("SELECT chat_id FROM pinned_chats WHERE user_id = ?").all(req.user.id).map(r => r.chat_id),
    archived: db.prepare("SELECT chat_id FROM archived_chats WHERE user_id = ?").all(req.user.id).map(r => r.chat_id),
    muted: db.prepare("SELECT chat_id FROM muted_chats WHERE user_id = ?").all(req.user.id).map(r => r.chat_id)
  });
});

// ══════════════════════════════════════════
// STATUSES
// ══════════════════════════════════════════
app.get("/api/statuses", authMW, (req, res) => {
  const contactIds = db.prepare("SELECT contact_id FROM contacts WHERE user_id = ?").all(req.user.id).map(r => r.contact_id);
  const allIds = [req.user.id, ...contactIds];
  const cutoff = Date.now() - 86400000;
  const result = allIds.map(uid => {
    const u = db.prepare("SELECT * FROM users WHERE id = ?").get(uid);
    if (!u) return null;
    const sts = db.prepare("SELECT * FROM statuses WHERE user_id = ? AND timestamp > ? ORDER BY timestamp ASC").all(uid, cutoff);
    return { user: safeUser(u), statuses: sts, isMe: uid === req.user.id };
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
  let views = JSON.parse(st.views || '[]');
  if (!views.includes(req.user.id)) {
    views.push(req.user.id);
    db.prepare("UPDATE statuses SET views = ? WHERE id = ?").run(JSON.stringify(views), req.params.id);
  }
  res.json({ ok: true, views });
});

app.delete("/api/status/:id", authMW, (req, res) => {
  db.prepare("DELETE FROM statuses WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════
// GROUPS
// ══════════════════════════════════════════
app.post("/api/groups", authMW, (req, res) => {
  const { name, memberIds } = req.body;
  if (!name || !memberIds?.length) return res.status(400).json({ error: "Required" });
  const id = uuidv4();
  const inviteLink = uuidv4().replace(/-/g, '').substring(0, 12);
  db.prepare("INSERT INTO groups (id, name, admin_id, invite_link) VALUES (?, ?, ?, ?)").run(id, name, req.user.id, inviteLink);
  for (const mId of [req.user.id, ...memberIds]) {
    const role = mId === req.user.id ? 'admin' : 'member';
    db.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)").run(id, mId, role);
  }
  const group = getGroupFull(id);
  group.members.forEach(mId => { if (userSockets.has(mId)) io.to(`user_${mId}`).emit("added_to_group", group); });
  // Send push to offline members
  for (const mId of memberIds) {
    if (!userSockets.has(mId)) sendPushNotif(mId, 'New Group', `You were added to group "${name}"`, { type: 'group', groupId: id });
  }
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
  io.emit("group_updated", getGroupFull(req.params.id));
  res.json({ ok: true });
});

app.put("/api/groups/:id", authMW, (req, res) => {
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(req.params.id);
  if (!g || g.admin_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  const { name, description, avatarImg, avatarColor } = req.body;
  if (name) db.prepare("UPDATE groups SET name = ? WHERE id = ?").run(name, req.params.id);
  if (description !== undefined) db.prepare("UPDATE groups SET description = ? WHERE id = ?").run(description, req.params.id);
  if (avatarImg !== undefined) db.prepare("UPDATE groups SET avatar_img = ? WHERE id = ?").run(avatarImg, req.params.id);
  if (avatarColor !== undefined) db.prepare("UPDATE groups SET avatar_color = ? WHERE id = ?").run(avatarColor, req.params.id);
  const updated = getGroupFull(req.params.id);
  io.emit("group_updated", updated);
  res.json(updated);
});

app.post("/api/groups/:id/add-member", authMW, (req, res) => {
  const { userId } = req.body;
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });
  const isMember = db.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").get(req.params.id, req.user.id);
  if (!isMember) return res.status(403).json({ error: "Forbidden" });
  db.prepare("INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, 'member')").run(req.params.id, userId);
  const updated = getGroupFull(req.params.id);
  io.emit("group_updated", updated);
  if (userSockets.has(userId)) io.to(`user_${userId}`).emit("added_to_group", updated);
  res.json(updated);
});

app.post("/api/groups/:id/remove-member", authMW, (req, res) => {
  const { userId } = req.body;
  const g = db.prepare("SELECT * FROM groups WHERE id = ?").get(req.params.id);
  if (!g || g.admin_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  db.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").run(req.params.id, userId);
  const updated = getGroupFull(req.params.id);
  io.emit("group_updated", updated);
  if (userSockets.has(userId)) io.to(`user_${userId}`).emit("removed_from_group", { groupId: req.params.id });
  res.json(updated);
});

// Group message reactions
app.post("/api/group-messages/:id/react", authMW, (req, res) => {
  const { emoji } = req.body;
  const msg = db.prepare("SELECT * FROM group_messages WHERE id = ?").get(req.params.id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  const reactions = JSON.parse(msg.reactions || '{}');
  if (!reactions[emoji]) reactions[emoji] = [];
  const idx = reactions[emoji].indexOf(req.user.id);
  if (idx >= 0) reactions[emoji].splice(idx, 1);
  else reactions[emoji].push(req.user.id);
  if (!reactions[emoji].length) delete reactions[emoji];
  db.prepare("UPDATE group_messages SET reactions = ? WHERE id = ?").run(JSON.stringify(reactions), req.params.id);
  io.to(`group_${msg.group_id}`).emit("group_message_reaction", { messageId: req.params.id, reactions });
  res.json({ ok: true });
});

// ══════════════════════════════════════════
// CALL LOGS
// ══════════════════════════════════════════
app.get("/api/call-logs", authMW, (req, res) => {
  const logs = db.prepare(`
    SELECT cl.*, 
      caller.username as caller_name, caller.avatar_color as caller_color, caller.avatar_img as caller_img,
      callee.username as callee_name, callee.avatar_color as callee_color, callee.avatar_img as callee_img
    FROM call_logs cl 
    JOIN users caller ON caller.id = cl.caller_id
    JOIN users callee ON callee.id = cl.callee_id
    WHERE cl.caller_id = ? OR cl.callee_id = ?
    ORDER BY cl.timestamp DESC LIMIT 50
  `).all(req.user.id, req.user.id);
  res.json(logs);
});

// ══════════════════════════════════════════
// NOTES (self chat)
// ══════════════════════════════════════════
app.get("/api/notes", authMW, (req, res) => {
  res.json(db.prepare("SELECT * FROM notes WHERE user_id = ? ORDER BY timestamp DESC").all(req.user.id));
});
app.post("/api/notes", authMW, (req, res) => {
  const { content } = req.body;
  const id = uuidv4();
  db.prepare("INSERT INTO notes (id, user_id, content) VALUES (?, ?, ?)").run(id, req.user.id, content);
  res.json({ id, content, timestamp: Date.now() });
});
app.delete("/api/notes/:id", authMW, (req, res) => {
  db.prepare("DELETE FROM notes WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════
// SCHEDULED MESSAGES
// ══════════════════════════════════════════
app.post("/api/schedule", authMW, (req, res) => {
  const { toUserId, groupId, content, type, scheduledAt } = req.body;
  const id = uuidv4();
  db.prepare("INSERT INTO scheduled_messages (id, from_user_id, to_user_id, group_id, content, type, scheduled_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, req.user.id, toUserId || null, groupId || null, content, type || 'text', scheduledAt);
  res.json({ ok: true, id });
});
app.get("/api/schedule", authMW, (req, res) => {
  res.json(db.prepare("SELECT * FROM scheduled_messages WHERE from_user_id = ? AND sent = 0 ORDER BY scheduled_at ASC").all(req.user.id));
});
app.delete("/api/schedule/:id", authMW, (req, res) => {
  db.prepare("DELETE FROM scheduled_messages WHERE id = ? AND from_user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════
// SEARCH
// ══════════════════════════════════════════
app.get("/api/search", authMW, (req, res) => {
  const q = req.query.q;
  if (!q) return res.json({ users: [], messages: [] });
  const users = db.prepare("SELECT * FROM users WHERE (username LIKE ? OR phone LIKE ?) AND id != ? LIMIT 10").all(`%${q}%`, `%${q}%`, req.user.id).map(safeUser);
  const contactIds = db.prepare("SELECT contact_id FROM contacts WHERE user_id = ?").all(req.user.id).map(r => r.contact_id);
  let messages = [];
  if (contactIds.length) {
    const roomIds = contactIds.map(id => `'${getRoomId(req.user.id, id)}'`).join(',');
    messages = db.prepare(`SELECT m.*, u.username as from_username FROM messages m JOIN users u ON u.id = m.from_user_id WHERE m.room_id IN (${roomIds}) AND m.content LIKE ? AND m.is_deleted = 0 ORDER BY m.timestamp DESC LIMIT 20`).all(`%${q}%`);
  }
  res.json({ users, messages });
});

// ══════════════════════════════════════════
// POLLS
// ══════════════════════════════════════════
app.post("/api/polls", authMW, (req, res) => {
  const { roomId, question, options } = req.body;
  const id = uuidv4();
  db.prepare("INSERT INTO polls (id, room_id, creator_id, question, options) VALUES (?, ?, ?, ?, ?)").run(id, roomId, req.user.id, question, JSON.stringify(options));
  res.json({ id, question, options, votes: {} });
});
app.post("/api/polls/:id/vote", authMW, (req, res) => {
  const { option } = req.body;
  const poll = db.prepare("SELECT * FROM polls WHERE id = ?").get(req.params.id);
  if (!poll) return res.status(404).json({ error: "Not found" });
  const votes = JSON.parse(poll.votes || '{}');
  // Remove existing vote
  Object.keys(votes).forEach(k => { votes[k] = votes[k].filter(uid => uid !== req.user.id); });
  if (!votes[option]) votes[option] = [];
  votes[option].push(req.user.id);
  db.prepare("UPDATE polls SET votes = ? WHERE id = ?").run(JSON.stringify(votes), req.params.id);
  io.to(poll.room_id).emit("poll_updated", { pollId: req.params.id, votes });
  res.json({ ok: true, votes });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ══════════════════════════════════════════
// SCHEDULED MESSAGES PROCESSOR
// ══════════════════════════════════════════
setInterval(() => {
  const now = Date.now();
  const pending = db.prepare("SELECT * FROM scheduled_messages WHERE sent = 0 AND scheduled_at <= ?").all(now);
  for (const sm of pending) {
    if (sm.to_user_id) {
      const roomId = getRoomId(sm.from_user_id, sm.to_user_id);
      const id = uuidv4();
      db.prepare("INSERT INTO messages (id, room_id, from_user_id, to_user_id, content, type, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, roomId, sm.from_user_id, sm.to_user_id, sm.content, sm.type, now);
      const msg = { id, roomId, fromUserId: sm.from_user_id, toUserId: sm.to_user_id, content: sm.content, type: sm.type, timestamp: now, read: false, deleted: false };
      io.to(`user_${sm.to_user_id}`).emit("new_message", msg);
      io.to(`user_${sm.from_user_id}`).emit("scheduled_sent", msg);
    }
    db.prepare("UPDATE scheduled_messages SET sent = 1 WHERE id = ?").run(sm.id);
  }
}, 10000);

// ══════════════════════════════════════════
// SOCKET
// ══════════════════════════════════════════
io.on("connection", (socket) => {
  socket.on("authenticate", (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.id;
      userSockets.set(decoded.id, socket.id);
      socket.join(`user_${decoded.id}`);
      db.prepare("SELECT group_id FROM group_members WHERE user_id = ?").all(decoded.id).forEach(({ group_id }) => socket.join(`group_${group_id}`));
      db.prepare("UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?").run(Date.now(), decoded.id);
      io.emit("user_online", { userId: decoded.id });
      socket.emit("authenticated", { userId: decoded.id });
    } catch { socket.emit("auth_error"); }
  });

  socket.on("send_message", ({ toUserId, content, type, fileUrl, fileName, fileSize, fileMime, replyTo, forwardedFrom }) => {
    if (!socket.userId) return;
    if (db.prepare("SELECT 1 FROM blocked WHERE user_id = ? AND blocked_id = ?").get(toUserId, socket.userId)) return;
    const roomId = getRoomId(socket.userId, toUserId);
    const id = uuidv4(), timestamp = Date.now();
    db.prepare("INSERT INTO messages (id, room_id, from_user_id, to_user_id, content, type, file_url, file_name, file_size, file_mime, reply_to, forwarded_from, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, roomId, socket.userId, toUserId, content || "", type || "text", fileUrl || null, fileName || null, fileSize || null, fileMime || null, replyTo || null, forwardedFrom || null, timestamp);
    const msg = { id, roomId, fromUserId: socket.userId, toUserId, content: content || "", type: type || "text", fileUrl: fileUrl || null, fileName: fileName || null, fileSize: fileSize || null, fileMime: fileMime || null, replyTo: replyTo || null, forwardedFrom: forwardedFrom || null, reactions: {}, timestamp, read: false, deleted: false };
    io.to(`user_${toUserId}`).emit("new_message", msg);
    socket.emit("message_sent", msg);
    if (!userSockets.has(toUserId)) {
      const sender = db.prepare("SELECT * FROM users WHERE id = ?").get(socket.userId);
      const targetUser = db.prepare("SELECT notifications_enabled FROM users WHERE id = ?").get(toUserId);
      if (targetUser?.notifications_enabled !== 0) {
        sendPushNotif(toUserId, sender?.username || "New Message",
          type === "text" ? (content || "") : `Sent a ${type}`,
          { type: 'message', fromUserId: socket.userId, fromUsername: sender?.username }
        );
      }
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
    const members = db.prepare("SELECT user_id FROM group_members WHERE group_id = ? AND user_id != ?").all(groupId, socket.userId);
    const group = db.prepare("SELECT name FROM groups WHERE id = ?").get(groupId);
    for (const { user_id } of members) {
      if (!userSockets.has(user_id)) {
        sendPushNotif(user_id, `${group?.name || 'Group'}: ${sender?.username}`,
          type === "text" ? (content || "") : `Sent a ${type}`,
          { type: 'group_message', groupId, fromUserId: socket.userId }
        );
      }
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
    if (db.prepare("SELECT id FROM group_messages WHERE id = ? AND from_user_id = ?").get(messageId, socket.userId)) {
      db.prepare("UPDATE group_messages SET is_deleted = 1, content = '', file_url = NULL WHERE id = ?").run(messageId);
    }
    io.to(`group_${groupId}`).emit("group_message_deleted", { messageId });
  });

  socket.on("call_user", ({ toUserId, offer, callId, callType }) => {
    const caller = db.prepare("SELECT * FROM users WHERE id = ?").get(socket.userId);
    const cId = callId || uuidv4();
    activeCalls.set(cId, { id: cId, callerId: socket.userId, calleeId: toUserId, status: "ringing", type: callType || "voice", startTime: Date.now() });
    io.to(`user_${toUserId}`).emit("incoming_call", { callId: cId, fromUserId: socket.userId, fromUsername: caller?.username, fromAvatarColor: caller?.avatar_color, fromAvatarImg: caller?.avatar_img, offer, callType: callType || "voice" });
    socket.emit("call_initiated", { callId: cId });
    // Push notification for call
    if (!userSockets.has(toUserId)) {
      sendPushNotif(toUserId,
        caller?.username || 'Incoming Call',
        callType === 'video' ? 'Incoming video call' : 'Incoming voice call',
        { type: 'call', callType, fromUserId: socket.userId, fromUsername: caller?.username, callId: cId }
      );
    }
  });
  socket.on("answer_call", ({ callId, toUserId, answer }) => {
    const call = activeCalls.get(callId);
    if (call) call.status = "active";
    io.to(`user_${toUserId}`).emit("call_answered", { callId, answer });
  });
  socket.on("reject_call", ({ callId, toUserId }) => {
    const call = activeCalls.get(callId);
    if (call) {
      db.prepare("INSERT INTO call_logs (id, caller_id, callee_id, call_type, status, duration, timestamp) VALUES (?, ?, ?, ?, 'missed', 0, ?)").run(uuidv4(), call.callerId, call.calleeId, call.type || 'voice', Date.now());
    }
    activeCalls.delete(callId);
    io.to(`user_${toUserId}`).emit("call_rejected", { callId });
  });
  socket.on("end_call", ({ callId, toUserId }) => {
    const call = activeCalls.get(callId);
    if (call) {
      const duration = Math.floor((Date.now() - (call.startTime || Date.now())) / 1000);
      db.prepare("INSERT INTO call_logs (id, caller_id, callee_id, call_type, status, duration, timestamp) VALUES (?, ?, ?, ?, 'completed', ?, ?)").run(uuidv4(), call.callerId, call.calleeId, call.type || 'voice', duration, Date.now());
    }
    activeCalls.delete(callId);
    io.to(`user_${toUserId}`).emit("call_ended", { callId });
  });
  socket.on("ice_candidate", ({ toUserId, candidate, callId }) => { io.to(`user_${toUserId}`).emit("ice_candidate", { candidate, callId, fromUserId: socket.userId }); });

  socket.on("presence", () => {
    db.prepare("UPDATE users SET last_seen = ?, is_online = 1 WHERE id = ?").run(Date.now(), socket.userId);
  });

  socket.on("disconnect", () => {
    if (socket.userId) {
      userSockets.delete(socket.userId);
      const now = Date.now();
      db.prepare("UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?").run(now, socket.userId);
      io.emit("user_offline", { userId: socket.userId, lastSeen: now });
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Spark Messenger v5 running on port ${PORT}`));
