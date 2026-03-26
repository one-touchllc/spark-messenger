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
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" }, maxHttpBufferSize: 1e8 });

app.use(cors());
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(passport.initialize());

const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "spark.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// --- DATABASE TABLES ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    phone TEXT UNIQUE,
    email TEXT UNIQUE,
    google_id TEXT UNIQUE,
    display_name TEXT NOT NULL,
    password TEXT,
    avatar_color TEXT DEFAULT '#25D366',
    avatar_img TEXT,
    status TEXT DEFAULT 'Hey there! I am using Spark Messenger.',
    about TEXT DEFAULT '',
    language TEXT DEFAULT 'en',
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')*1000)
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
    id TEXT PRIMARY KEY, room_id TEXT NOT NULL, from_user_id TEXT NOT NULL, to_user_id TEXT NOT NULL,
    content TEXT DEFAULT '', type TEXT DEFAULT 'text', file_url TEXT, file_name TEXT, file_size INTEGER, file_mime TEXT,
    reply_to_id TEXT, reply_preview TEXT, forwarded INTEGER DEFAULT 0, timestamp INTEGER DEFAULT (strftime('%s','now')*1000),
    is_read INTEGER DEFAULT 0, is_deleted INTEGER DEFAULT 0, is_edited INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room_id);
  CREATE TABLE IF NOT EXISTS message_reactions (
    message_id TEXT NOT NULL, user_id TEXT NOT NULL, emoji TEXT NOT NULL, PRIMARY KEY (message_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, admin_id TEXT NOT NULL, avatar_color TEXT DEFAULT '#25D366',
    avatar_img TEXT, description TEXT DEFAULT '', wallpaper TEXT DEFAULT '', created_at INTEGER DEFAULT (strftime('%s','now')*1000)
  );
  CREATE TABLE IF NOT EXISTS group_members ( group_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (group_id, user_id) );
  CREATE TABLE IF NOT EXISTS group_messages (
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL, from_user_id TEXT NOT NULL, content TEXT DEFAULT '',
    type TEXT DEFAULT 'text', file_url TEXT, file_name TEXT, file_size INTEGER, file_mime TEXT,
    reply_to_id TEXT, reply_preview TEXT, forwarded INTEGER DEFAULT 0, timestamp INTEGER DEFAULT (strftime('%s','now')*1000),
    is_deleted INTEGER DEFAULT 0, is_edited INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS statuses ( id TEXT PRIMARY KEY, user_id TEXT NOT NULL, content TEXT NOT NULL, type TEXT DEFAULT 'text', timestamp INTEGER DEFAULT (strftime('%s','now')*1000) );
  CREATE TABLE IF NOT EXISTS pinned_chats ( user_id TEXT NOT NULL, chat_id TEXT NOT NULL, PRIMARY KEY (user_id, chat_id) );
  CREATE TABLE IF NOT EXISTS archived_chats ( user_id TEXT NOT NULL, chat_id TEXT NOT NULL, PRIMARY KEY (user_id, chat_id) );
  CREATE TABLE IF NOT EXISTS push_subscriptions ( user_id TEXT PRIMARY KEY, subscription TEXT NOT NULL );
  CREATE TABLE IF NOT EXISTS chat_wallpapers ( user_id TEXT NOT NULL, chat_id TEXT NOT NULL, wallpaper TEXT NOT NULL, PRIMARY KEY (user_id, chat_id) );
  CREATE TABLE IF NOT EXISTS starred_messages ( user_id TEXT NOT NULL, message_id TEXT NOT NULL, PRIMARY KEY (user_id, message_id) );
`);

const JWT_SECRET = process.env.JWT_SECRET || "sparkmessenger_v5_2024";
let VAPID_PUBLIC = process.env.VAPID_PUBLIC;
let VAPID_PRIVATE = process.env.VAPID_PRIVATE;
if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
  const keys = webpush.generateVAPIDKeys();
  VAPID_PUBLIC = keys.publicKey; VAPID_PRIVATE = keys.privateKey;
}
try { webpush.setVapidDetails("mailto:admin@sparkmessenger.app", VAPID_PUBLIC, VAPID_PRIVATE); } catch(e) {}

// --- HELPERS ---
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
  return { id: u.id, phone: u.phone, email: u.email, displayName: u.display_name, avatarColor: u.avatar_color, avatarImg: u.avatar_img, status: u.status, about: u.about, language: u.language, lastSeen: u.last_seen };
}
function fmtMsg(m) {
  return { id: m.id, roomId: m.room_id, fromUserId: m.from_user_id, toUserId: m.to_user_id, content: m.is_deleted ? "" : (m.content || ""), type: m.type, fileUrl: m.is_deleted ? null : m.file_url, fileName: m.file_name, fileSize: m.file_size, fileMime: m.file_mime, replyToId: m.reply_to_id, replyPreview: m.reply_preview, forwarded: !!m.forwarded, timestamp: m.timestamp, read: !!m.is_read, deleted: !!m.is_deleted, edited: !!m.is_edited };
}

// --- GOOGLE STRATEGY ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://spark-messenger.up.railway.app/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = db.prepare("SELECT * FROM users WHERE google_id = ? OR email = ?").get(profile.id, profile.emails[0].value);
      if (!user) {
        const id = uuidv4();
        const colors = ["#25D366","#128C7E","#075E54","#34B7F1","#FF6B6B"];
        const avatarColor = colors[Math.floor(Math.random() * colors.length)];
        db.prepare("INSERT INTO users (id, google_id, email, display_name, avatar_img, avatar_color) VALUES (?,?,?,?,?,?)")
          .run(id, profile.id, profile.emails[0].value, profile.displayName, profile.photos[0]?.value, avatarColor);
        user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
      }
      return done(null, user);
    } catch (err) { return done(err, null); }
  }
));

// --- ROUTES ---
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", 
  passport.authenticate("google", { session: false, failureRedirect: "/login" }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email }, JWT_SECRET, { expiresIn: "30d" });
    res.redirect(`/?token=${token}`);
  }
);

app.post("/api/register", async (req, res) => {
  const { phone, displayName, password } = req.body;
  const cleanPhone = phone.replace(/\D/g, "");
  if (db.prepare("SELECT id FROM users WHERE phone = ?").get(cleanPhone)) return res.status(409).json({ error: "Already registered!" });
  const id = uuidv4();
  db.prepare("INSERT INTO users (id, phone, display_name, password) VALUES (?,?,?,?)").run(id, cleanPhone, displayName, await bcrypt.hash(password, 10));
  const token = jwt.sign({ id, phone: cleanPhone }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: safeUser(db.prepare("SELECT * FROM users WHERE id = ?").get(id)) });
});

app.post("/api/login", async (req, res) => {
  const { phone, password } = req.body;
  const cleanPhone = phone.replace(/\D/g, "");
  const user = db.prepare("SELECT * FROM users WHERE phone = ?").get(cleanPhone);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid" });
  const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: safeUser(user) });
});

app.get("/api/contacts", authMW, (req, res) => {
  const rows = db.prepare(`SELECT u.*, c.nickname FROM contacts c JOIN users u ON u.id = c.contact_id WHERE c.user_id = ?`).all(req.user.id);
  res.json(rows.map(u => ({ ...safeUser(u), nickname: u.nickname, online: userSockets.has(u.id) })));
});

app.post("/api/contacts/add", authMW, (req, res) => {
  const { phone } = req.body;
  const found = db.prepare("SELECT * FROM users WHERE phone = ?").get(phone.replace(/\D/g, ""));
  if (!found) return res.status(404).json({ error: "Not found" });
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)").run(req.user.id, found.id);
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?,?)").run(found.id, req.user.id);
  res.json({ user: safeUser(found) });
});

app.get("/api/messages/:userId", authMW, (req, res) => {
  const msgs = db.prepare("SELECT * FROM messages WHERE room_id = ? ORDER BY timestamp ASC").all(getRoomId(req.user.id, req.params.userId)).map(fmtMsg);
  res.json(msgs);
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// --- SOCKETS ---
io.on("connection", (socket) => {
  socket.on("authenticate", (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.id;
      userSockets.set(decoded.id, socket.id);
      socket.join(`user_${decoded.id}`);
      io.emit("user_online", { userId: decoded.id });
    } catch { socket.emit("auth_error"); }
  });

  socket.on("send_message", ({ toUserId, content, type }) => {
    if (!socket.userId) return;
    const id = uuidv4(), timestamp = Date.now();
    db.prepare("INSERT INTO messages (id,room_id,from_user_id,to_user_id,content,type,timestamp) VALUES (?,?,?,?,?,?,?)").run(id, getRoomId(socket.userId, toUserId), socket.userId, toUserId, content, type || "text", timestamp);
    io.to(`user_${toUserId}`).emit("new_message", { id, fromUserId: socket.userId, content, type, timestamp });
  });

  socket.on("disconnect", () => {
    if (socket.userId) {
      userSockets.delete(socket.userId);
      io.emit("user_offline", { userId: socket.userId });
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
