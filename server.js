/**
 * Spark Messenger - server.js (Full Featured with Data Persistence)
 * Run: npm install && node server.js
 */
const express = require('express'); // 1. Sabse pehle express lao
const app = express();            // 2. Ab 'app' initialize karo

// 3. AB YE WALA CODE LIKHO (Initialization ke BAAD)
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "frame-ancestors 'self' https://sparkmessenger.unaux.com");
    res.removeHeader("X-Frame-Options");
    next();
});

// Baki ka code (Routes, Listen, etc.) iske niche aayega
app.get('/', (req, res) => {
    res.send('Server is running!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const webpush = require("web-push");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "spark_jwt_secret_" + crypto.randomBytes(16).toString("hex");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = path.join(__dirname, "data");

let VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || "";
let VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || "";

if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  const vapidKeys = webpush.generateVAPIDKeys();
  VAPID_PUBLIC_KEY = vapidKeys.publicKey;
  VAPID_PRIVATE_KEY = vapidKeys.privateKey;
}

webpush.setVapidDetails(
  "mailto:admin@sparkmessenger.app",
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

// Create necessary directories
[UPLOAD_DIR, PUBLIC_DIR, DATA_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Data persistence functions
function saveDataToFile(filename, data) {
  try {
    const filePath = path.join(DATA_DIR, filename);
    let dataToSave;
    
    if (data instanceof Map) {
      dataToSave = Array.from(data.entries());
    } else {
      dataToSave = data;
    }
    
    fs.writeFileSync(filePath, JSON.stringify(dataToSave, null, 2));
  } catch (e) {
    console.error(`Error saving ${filename}:`, e.message);
  }
}

function loadDataFromFile(filename, isMap = false) {
  try {
    const filePath = path.join(DATA_DIR, filename);
    if (!fs.existsSync(filePath)) return isMap ? new Map() : null;
    
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    
    return isMap ? new Map(parsed) : parsed;
  } catch (e) {
    console.error(`Error loading ${filename}:`, e.message);
    return isMap ? new Map() : null;
  }
}

// Initialize DB with persistence
const DB = {
  users: loadDataFromFile('users.json', true) || new Map(),
  userByPhone: loadDataFromFile('userByPhone.json', true) || new Map(),
  messages: loadDataFromFile('messages.json', true) || new Map(),
  groups: loadDataFromFile('groups.json', true) || new Map(),
  statuses: loadDataFromFile('statuses.json', true) || new Map(),
  contacts: loadDataFromFile('contacts.json', true) || new Map(),
  pinned: loadDataFromFile('pinned.json', true) || new Map(),
  archived: loadDataFromFile('archived.json', true) || new Map(),
  wallpapers: loadDataFromFile('wallpapers.json', true) || new Map(),
  starred: loadDataFromFile('starred.json', true) || new Map(),
  blocked: loadDataFromFile('blocked.json', true) || new Map(),
  pushSubs: loadDataFromFile('pushSubs.json', true) || new Map(),
  callHistory: loadDataFromFile('callHistory.json', true) || new Map(),
  polls: loadDataFromFile('polls.json', true) || new Map(),
  groupCalls: new Map(), // Group calls are temporary, no need to persist
  locations: loadDataFromFile('locations.json', true) || new Map(),
};

// Convert Set data back from arrays
function convertArrayToSet(mapData) {
  const result = new Map();
  for (const [key, value] of mapData) {
    result.set(key, new Set(value));
  }
  return result;
}

// Load special Map<string, Set> structures
if (fs.existsSync(path.join(DATA_DIR, 'contacts.json'))) {
  const contactsData = loadDataFromFile('contacts.json', true);
  DB.contacts = convertArrayToSet(contactsData);
}
if (fs.existsSync(path.join(DATA_DIR, 'pinned.json'))) {
  const pinnedData = loadDataFromFile('pinned.json', true);
  DB.pinned = convertArrayToSet(pinnedData);
}
if (fs.existsSync(path.join(DATA_DIR, 'archived.json'))) {
  const archivedData = loadDataFromFile('archived.json', true);
  DB.archived = convertArrayToSet(archivedData);
}
if (fs.existsSync(path.join(DATA_DIR, 'starred.json'))) {
  const starredData = loadDataFromFile('starred.json', true);
  DB.starred = convertArrayToSet(starredData);
}
if (fs.existsSync(path.join(DATA_DIR, 'blocked.json'))) {
  const blockedData = loadDataFromFile('blocked.json', true);
  DB.blocked = convertArrayToSet(blockedData);
}

// Auto-save function - saves all data periodically
function saveAllData() {
  // Save Maps directly
  saveDataToFile('users.json', DB.users);
  saveDataToFile('userByPhone.json', DB.userByPhone);
  saveDataToFile('messages.json', DB.messages);
  saveDataToFile('groups.json', DB.groups);
  saveDataToFile('statuses.json', DB.statuses);
  saveDataToFile('wallpapers.json', DB.wallpapers);
  saveDataToFile('pushSubs.json', DB.pushSubs);
  saveDataToFile('callHistory.json', DB.callHistory);
  saveDataToFile('polls.json', DB.polls);
  saveDataToFile('locations.json', DB.locations);
  
  // Convert Sets to Arrays before saving
  const contactsArray = new Map();
  for (const [key, value] of DB.contacts) {
    contactsArray.set(key, Array.from(value));
  }
  saveDataToFile('contacts.json', contactsArray);
  
  const pinnedArray = new Map();
  for (const [key, value] of DB.pinned) {
    pinnedArray.set(key, Array.from(value));
  }
  saveDataToFile('pinned.json', pinnedArray);
  
  const archivedArray = new Map();
  for (const [key, value] of DB.archived) {
    archivedArray.set(key, Array.from(value));
  }
  saveDataToFile('archived.json', archivedArray);
  
  const starredArray = new Map();
  for (const [key, value] of DB.starred) {
    starredArray.set(key, Array.from(value));
  }
  saveDataToFile('starred.json', starredArray);
  
  const blockedArray = new Map();
  for (const [key, value] of DB.blocked) {
    blockedArray.set(key, Array.from(value));
  }
  saveDataToFile('blocked.json', blockedArray);
  
  console.log(`💾 Data saved at ${new Date().toLocaleTimeString()}`);
}

// Auto-save every 30 seconds
setInterval(saveAllData, 30000);

// Save on process exit
process.on('SIGINT', () => {
  console.log('\n💾 Saving data before exit...');
  saveAllData();
  console.log('✅ Data saved. Exiting.');
  process.exit(0);
});

process.on('SIGTERM', () => {
  saveAllData();
  process.exit(0);
});

const getSet = (map, key) => {
  if (!map.has(key)) map.set(key, new Set());
  return map.get(key);
};
const getMap = (map, key) => {
  if (!map.has(key)) map.set(key, {});
  return map.get(key);
};
const getArr = (map, key) => {
  if (!map.has(key)) map.set(key, []);
  return map.get(key);
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
  transports: ["websocket", "polling"],
});

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/uploads", express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  },
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized" });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

const socketUserMap = new Map();
const userSocketMap = new Map();

const AVATAR_COLORS = [
  "#1565C0",
  "#0D47A1",
  "#1976D2",
  "#2196F3",
  "#00897B",
  "#388E3C",
  "#F57C00",
  "#E64A19",
  "#6A1B9A",
  "#AD1457",
  "#00838F",
  "#37474F",
];
function randomColor() {
  return AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];
}

// AUTH
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "Phone and password required" });
    const userId = DB.userByPhone.get(phone);
    if (!userId)
      return res.status(401).json({ error: "Phone number not registered" });
    const user = DB.users.get(userId);
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Wrong password" });
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
    const { passwordHash, ...safeUser } = user;
    res.json({ user: safeUser, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const { phone, displayName, password } = req.body;
    if (!phone || !displayName || !password)
      return res.status(400).json({ error: "All fields required" });
    if (DB.userByPhone.has(phone))
      return res.status(400).json({ error: "Phone already registered" });
    if (password.length < 4)
      return res
        .status(400)
        .json({ error: "Password too short (min 4 chars)" });
    const passwordHash = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const user = {
      id: userId,
      phone,
      displayName,
      passwordHash,
      avatarColor: randomColor(),
      avatarImg: null,
      status: "Hey there! I'm on Spark.",
      about: "",
      lastSeen: Date.now(),
      createdAt: Date.now(),
    };
    DB.users.set(userId, user);
    DB.userByPhone.set(phone, userId);
    saveAllData(); // Save after registration
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "30d" });
    const { passwordHash: _, ...safeUser } = user;
    res.json({ user: safeUser, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PROFILE
app.put("/api/profile", authMiddleware, (req, res) => {
  const user = DB.users.get(req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });
  const { display_name, status, about, avatar_img } = req.body;
  if (display_name) user.displayName = display_name;
  if (status !== undefined) user.status = status;
  if (about !== undefined) user.about = about;
  if (avatar_img) user.avatarImg = avatar_img;
  DB.users.set(req.userId, user);
  saveAllData(); // Save after profile update
  const { passwordHash, ...safeUser } = user;
  broadcastToContacts(req.userId, "profile_updated", safeUser);
  res.json(safeUser);
});

app.get("/api/profile", authMiddleware, (req, res) => {
  const user = DB.users.get(req.userId);
  if (!user) return res.status(404).json({ error: "Not found" });
  const { passwordHash, ...safeUser } = user;
  res.json(safeUser);
});

// CONTACTS
app.get("/api/contacts", authMiddleware, (req, res) => {
  const myContacts = getSet(DB.contacts, req.userId);
  const result = [];
  for (const cId of myContacts) {
    const u = DB.users.get(cId);
    if (!u) continue;
    const { passwordHash, ...safe } = u;
    result.push({ ...safe, online: userSocketMap.has(cId) });
  }
  res.json(result);
});

app.post("/api/contacts/add", authMiddleware, (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: "Phone required" });
  const targetId = DB.userByPhone.get(phone);
  if (!targetId)
    return res.status(404).json({ error: "User not found with this number" });
  if (targetId === req.userId)
    return res.status(400).json({ error: "Cannot add yourself" });
  getSet(DB.contacts, req.userId).add(targetId);
  saveAllData(); // Save after adding contact
  const target = DB.users.get(targetId);
  const { passwordHash, ...safe } = target;
  const tSocket = userSocketMap.get(targetId);
  if (tSocket) {
    const me = DB.users.get(req.userId);
    const { passwordHash: _, ...meS } = me;
    io.to(tSocket).emit("contact_added", { user: meS });
  }
  res.json({ user: { ...safe, online: userSocketMap.has(targetId) } });
});

app.delete("/api/contacts/:id", authMiddleware, (req, res) => {
  getSet(DB.contacts, req.userId).delete(req.params.id);
  saveAllData(); // Save after deleting contact
  res.json({ ok: true });
});

// MESSAGES
app.get("/api/messages/:userId", authMiddleware, (req, res) => {
  const msgs = getConversation(req.userId, req.params.userId);
  res.json(msgs);
});

app.get("/api/messages/:userId/by-date", authMiddleware, (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: "date required" });
  const start = new Date(date).setHours(0, 0, 0, 0);
  const end = new Date(date).setHours(23, 59, 59, 999);
  const msgs = getConversation(req.userId, req.params.userId).filter(
    (m) => m.timestamp >= start && m.timestamp <= end
  );
  res.json(msgs);
});

app.post("/api/messages/:id/react", authMiddleware, (req, res) => {
  const { emoji } = req.body;
  const msg = DB.messages.get(req.params.id);
  if (!msg) return res.status(404).json({ error: "Message not found" });
  if (!msg.reactions) msg.reactions = [];
  const existing = msg.reactions.findIndex(
    (r) => r.userId === req.userId && r.emoji === emoji
  );
  if (existing >= 0) msg.reactions.splice(existing, 1);
  else msg.reactions.push({ userId: req.userId, emoji });
  saveAllData(); // Save after reaction
  const otherUserId =
    msg.fromUserId === req.userId ? msg.toUserId : msg.fromUserId;
  const s = userSocketMap.get(otherUserId);
  if (s)
    io.to(s).emit("reaction_update", {
      messageId: msg.id,
      reactions: msg.reactions,
    });
  const mine = userSocketMap.get(req.userId);
  if (mine)
    io.to(mine).emit("reaction_update", {
      messageId: msg.id,
      reactions: msg.reactions,
    });
  res.json({ ok: true });
});

app.post("/api/messages/:id/star", authMiddleware, (req, res) => {
  const starred = getSet(DB.starred, req.userId);
  if (starred.has(req.params.id)) starred.delete(req.params.id);
  else starred.add(req.params.id);
  saveAllData(); // Save after starring
  res.json({ ok: true });
});

app.get("/api/starred", authMiddleware, (req, res) => {
  const starred = getSet(DB.starred, req.userId);
  const msgs = [];
  for (const id of starred) {
    const m = DB.messages.get(id);
    if (m) msgs.push(m);
  }
  res.json(msgs.sort((a, b) => b.timestamp - a.timestamp));
});

app.put("/api/messages/:id/edit", authMiddleware, (req, res) => {
  const { content } = req.body;
  const msg = DB.messages.get(req.params.id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  if (msg.fromUserId !== req.userId)
    return res.status(403).json({ error: "Forbidden" });
  msg.content = content;
  msg.edited = true;
  saveAllData(); // Save after editing
  emitToUser(msg.toUserId, "message_edited", { messageId: msg.id, content });
  res.json({ ok: true });
});

// GROUPS
app.get("/api/groups", authMiddleware, (req, res) => {
  const result = [];
  for (const [, g] of DB.groups) {
    if (g.members.includes(req.userId)) result.push(g);
  }
  res.json(result);
});

app.post("/api/groups", authMiddleware, (req, res) => {
  const { name, memberIds } = req.body;
  if (!name || !memberIds?.length)
    return res.status(400).json({ error: "Name and members required" });
  const groupId = uuidv4();
  const members = [...new Set([req.userId, ...memberIds])];
  const group = {
    id: groupId,
    name,
    members,
    admins: [req.userId],
    createdBy: req.userId,
    avatarColor: randomColor(),
    avatarImg: null,
    description: "",
    canMembersSendMessages: true,
    createdAt: Date.now(),
  };
  DB.groups.set(groupId, group);
  saveAllData(); // Save after creating group
  members.forEach((uid) => {
    if (uid !== req.userId) emitToUser(uid, "added_to_group", group);
  });
  res.json(group);
});

app.put("/api/groups/:id", authMiddleware, (req, res) => {
  const g = DB.groups.get(req.params.id);
  if (!g) return res.status(404).json({ error: "Group not found" });
  if (!g.admins.includes(req.userId))
    return res.status(403).json({ error: "Admins only" });
  const { name, description, avatarImg, canMembersSendMessages } = req.body;
  if (name) g.name = name;
  if (description !== undefined) g.description = description;
  if (avatarImg !== undefined) g.avatarImg = avatarImg;
  if (canMembersSendMessages !== undefined)
    g.canMembersSendMessages = canMembersSendMessages;
  saveAllData(); // Save after updating group
  g.members.forEach((uid) => emitToUser(uid, "group_updated", g));
  res.json(g);
});

app.post("/api/groups/:id/add-admin", authMiddleware, (req, res) => {
  const g = DB.groups.get(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });
  if (!g.admins.includes(req.userId))
    return res.status(403).json({ error: "Admins only" });
  const { userId } = req.body;
  if (!g.admins.includes(userId)) g.admins.push(userId);
  saveAllData(); // Save after adding admin
  g.members.forEach((uid) => emitToUser(uid, "group_updated", g));
  res.json(g);
});

app.post("/api/groups/:id/remove-member", authMiddleware, (req, res) => {
  const g = DB.groups.get(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });
  if (!g.admins.includes(req.userId))
    return res.status(403).json({ error: "Admins only" });
  const { userId } = req.body;
  g.members = g.members.filter((m) => m !== userId);
  g.admins = g.admins.filter((a) => a !== userId);
  saveAllData(); // Save after removing member
  emitToUser(userId, "removed_from_group", { groupId: g.id });
  g.members.forEach((uid) => emitToUser(uid, "group_updated", g));
  res.json(g);
});

app.get("/api/groups/:id/messages", authMiddleware, (req, res) => {
  const g = DB.groups.get(req.params.id);
  if (!g || !g.members.includes(req.userId))
    return res.status(403).json({ error: "Forbidden" });
  const msgs = [];
  for (const [, m] of DB.messages) {
    if (m.groupId === req.params.id) msgs.push(m);
  }
  res.json(msgs.sort((a, b) => a.timestamp - b.timestamp));
});

app.get("/api/groups/:id/messages/by-date", authMiddleware, (req, res) => {
  const g = DB.groups.get(req.params.id);
  if (!g || !g.members.includes(req.userId))
    return res.status(403).json({ error: "Forbidden" });
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: "date required" });
  const start = new Date(date).setHours(0, 0, 0, 0);
  const end = new Date(date).setHours(23, 59, 59, 999);
  const msgs = [];
  for (const [, m] of DB.messages) {
    if (
      m.groupId === req.params.id &&
      m.timestamp >= start &&
      m.timestamp <= end
    )
      msgs.push(m);
  }
  res.json(msgs.sort((a, b) => a.timestamp - b.timestamp));
});

app.post("/api/groups/:id/leave", authMiddleware, (req, res) => {
  const g = DB.groups.get(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });
  g.members = g.members.filter((m) => m !== req.userId);
  g.admins = g.admins.filter((a) => a !== req.userId);
  saveAllData(); // Save after leaving group
  g.members.forEach((uid) => emitToUser(uid, "group_updated", g));
  res.json({ ok: true });
});

app.get("/api/groups/:id/media", authMiddleware, (req, res) => {
  const g = DB.groups.get(req.params.id);
  if (!g || !g.members.includes(req.userId))
    return res.status(403).json({ error: "Forbidden" });
  const media = [],
    links = [],
    docs = [];
  for (const [, m] of DB.messages) {
    if (m.groupId !== req.params.id || m.deleted) continue;
    if (m.type === "image" || m.type === "video") media.push(m);
    else if (m.type === "text" && m.content?.match(/https?:\/\/\S+/))
      links.push(m);
    else if (m.fileUrl) docs.push(m);
  }
  res.json({ media, links, docs });
});

// POLLS
app.post("/api/polls", authMiddleware, (req, res) => {
  const { question, options, multipleAnswers } = req.body;
  if (!question || !options?.length)
    return res.status(400).json({ error: "Question and options required" });
  const pollId = uuidv4();
  const poll = {
    id: pollId,
    question,
    options: options.map((o, i) => ({ id: i, text: o, voters: [] })),
    createdBy: req.userId,
    multipleAnswers: multipleAnswers || false,
    createdAt: Date.now(),
  };
  DB.polls.set(pollId, poll);
  saveAllData(); // Save after creating poll
  res.json(poll);
});

app.post("/api/polls/:id/vote", authMiddleware, (req, res) => {
  const poll = DB.polls.get(req.params.id);
  if (!poll) return res.status(404).json({ error: "Poll not found" });
  const { optionIds } = req.body;
  poll.options.forEach((o) => {
    o.voters = o.voters.filter((v) => v !== req.userId);
  });
  const toVote = poll.multipleAnswers ? optionIds : [optionIds[0]];
  toVote.forEach((oid) => {
    const opt = poll.options.find((o) => o.id === oid);
    if (opt && !opt.voters.includes(req.userId)) opt.voters.push(req.userId);
  });
  saveAllData(); // Save after voting
  res.json(poll);
});

app.get("/api/polls/:id", authMiddleware, (req, res) => {
  const poll = DB.polls.get(req.params.id);
  if (!poll) return res.status(404).json({ error: "Not found" });
  res.json(poll);
});

// STATUS
app.post("/api/status", authMiddleware, (req, res) => {
  const { content, type, overlays, bgColor, textStyle } = req.body;
  const statusEntry = {
    id: uuidv4(),
    content,
    type: type || "text",
    overlays: overlays || [],
    bgColor: bgColor || null,
    textStyle: textStyle || null,
    timestamp: Date.now(),
  };
  const arr = getArr(DB.statuses, req.userId);
  arr.push(statusEntry);
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  DB.statuses.set(
    req.userId,
    arr.filter((s) => s.timestamp > cutoff)
  );
  saveAllData(); // Save after posting status
  broadcastToContacts(req.userId, "new_status", { userId: req.userId });
  res.json({ ok: true });
});

app.get("/api/statuses", authMiddleware, (req, res) => {
  const result = [];
  const myContacts = getSet(DB.contacts, req.userId);
  const allUserIds = [req.userId, ...myContacts];
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const uid of allUserIds) {
    const user = DB.users.get(uid);
    if (!user) continue;
    const statuses = getArr(DB.statuses, uid).filter(
      (s) => s.timestamp > cutoff
    );
    if (uid === req.userId || statuses.length > 0) {
      const { passwordHash, ...safeUser } = user;
      result.push({ user: safeUser, statuses, isMe: uid === req.userId });
    }
  }
  res.json(result);
});

// CALL HISTORY
app.get("/api/call-history", authMiddleware, (req, res) => {
  const history = getArr(DB.callHistory, req.userId);
  res.json(history.sort((a, b) => b.timestamp - a.timestamp).slice(0, 100));
});

function addCallHistory(userId, record) {
  const arr = getArr(DB.callHistory, userId);
  arr.push(record);
  if (arr.length > 200) arr.splice(0, arr.length - 200);
  saveAllData(); // Save after adding call history
}

// META
app.get("/api/meta", authMiddleware, (req, res) => {
  res.json({
    pinned: [...getSet(DB.pinned, req.userId)],
    archived: [...getSet(DB.archived, req.userId)],
  });
});
app.post("/api/pin/:chatId", authMiddleware, (req, res) => {
  getSet(DB.pinned, req.userId).add(req.params.chatId);
  saveAllData(); // Save after pinning
  res.json({ ok: true });
});
app.post("/api/unpin/:chatId", authMiddleware, (req, res) => {
  getSet(DB.pinned, req.userId).delete(req.params.chatId);
  saveAllData(); // Save after unpinning
  res.json({ ok: true });
});
app.post("/api/archive/:chatId", authMiddleware, (req, res) => {
  getSet(DB.archived, req.userId).add(req.params.chatId);
  saveAllData(); // Save after archiving
  res.json({ ok: true });
});
app.post("/api/unarchive/:chatId", authMiddleware, (req, res) => {
  getSet(DB.archived, req.userId).delete(req.params.chatId);
  saveAllData(); // Save after unarchiving
  res.json({ ok: true });
});
app.get("/api/wallpapers", authMiddleware, (req, res) => {
  res.json(getMap(DB.wallpapers, req.userId));
});
app.put("/api/wallpaper/:chatId", authMiddleware, (req, res) => {
  const wp = getMap(DB.wallpapers, req.userId);
  wp[req.params.chatId] = req.body.wallpaper || "";
  saveAllData(); // Save after setting wallpaper
  res.json({ ok: true });
});
app.post("/api/block/:userId", authMiddleware, (req, res) => {
  getSet(DB.blocked, req.userId).add(req.params.userId);
  saveAllData(); // Save after blocking
  res.json({ ok: true });
});

// SEARCH
app.get("/api/search/messages", authMiddleware, (req, res) => {
  const q = (req.query.q || "").toLowerCase();
  const dateFrom = req.query.dateFrom ? parseInt(req.query.dateFrom) : null;
  const dateTo = req.query.dateTo ? parseInt(req.query.dateTo) : null;
  if (!q && !dateFrom) return res.json([]);
  const results = [];
  for (const [, m] of DB.messages) {
    if (m.deleted) continue;
    if (m.fromUserId !== req.userId && m.toUserId !== req.userId) continue;
    if (q && m.content && !m.content.toLowerCase().includes(q)) continue;
    if (dateFrom && m.timestamp < dateFrom) continue;
    if (dateTo && m.timestamp > dateTo) continue;
    results.push(m);
  }
  res.json(results.sort((a, b) => b.timestamp - a.timestamp).slice(0, 50));
});

// FILE UPLOAD
app.post("/api/upload", authMiddleware, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({
    fileUrl,
    fileName: req.file.originalname,
    fileSize: req.file.size,
    fileMime: req.file.mimetype,
  });
});

app.get("/api/vapid-public-key", (req, res) => {
  res.json({ key: VAPID_PUBLIC_KEY });
});
app.post("/api/push-subscribe", authMiddleware, (req, res) => {
  DB.pushSubs.set(req.userId, req.body.subscription);
  saveAllData(); // Save after push subscription
  res.json({ ok: true });
});

// SOCKET.IO
io.on("connection", (socket) => {
  socket.on("authenticate", (token) => {
    try {
      const { userId } = jwt.verify(token, JWT_SECRET);
      socketUserMap.set(socket.id, userId);
      userSocketMap.set(userId, socket.id);
      socket.userId = userId;
      socket.emit("authenticated");
      const user = DB.users.get(userId);
      if (user) user.lastSeen = Date.now();
      broadcastToContacts(userId, "user_online", { userId });
    } catch {
      socket.emit("auth_error", "Invalid token");
    }
  });

  socket.on("send_message", (data) => {
    if (!socket.userId) return;
    const {
      toUserId,
      content,
      type,
      fileUrl,
      fileName,
      fileSize,
      fileMime,
      replyToId,
      replyPreview,
      forwarded,
      pollId,
      location,
    } = data;
    if (getSet(DB.blocked, toUserId).has(socket.userId)) return;
    const msg = {
      id: uuidv4(),
      fromUserId: socket.userId,
      toUserId,
      content: content || "",
      type: type || "text",
      fileUrl: fileUrl || null,
      fileName: fileName || null,
      fileSize: fileSize || null,
      fileMime: fileMime || null,
      replyToId: replyToId || null,
      replyPreview: replyPreview || null,
      forwarded: forwarded || false,
      reactions: [],
      read: false,
      edited: false,
      deleted: false,
      timestamp: Date.now(),
      pollId: pollId || null,
      location: location || null,
    };
    DB.messages.set(msg.id, msg);
    if (pollId) DB.polls.set(pollId, data.pollData || DB.polls.get(pollId));
    saveAllData(); // Save after sending message
    const recipientSocket = userSocketMap.get(toUserId);
    if (recipientSocket) {
      io.to(recipientSocket).emit("new_message", msg);
      sendPushNotification(toUserId, {
        title: DB.users.get(socket.userId)?.displayName || "Message",
        body: type === "text" ? content || "" : `Sent a ${type}`,
      });
    }
    socket.emit("message_sent", msg);
  });

  socket.on("send_group_message", (data) => {
    if (!socket.userId) return;
    const {
      groupId,
      content,
      type,
      fileUrl,
      fileName,
      fileSize,
      fileMime,
      replyToId,
      replyPreview,
      pollId,
      location,
    } = data;
    const group = DB.groups.get(groupId);
    if (!group || !group.members.includes(socket.userId)) return;
    if (!group.canMembersSendMessages && !group.admins.includes(socket.userId))
      return;
    const sender = DB.users.get(socket.userId);
    const msg = {
      id: uuidv4(),
      fromUserId: socket.userId,
      fromUsername: sender?.displayName || "Unknown",
      groupId,
      content: content || "",
      type: type || "text",
      fileUrl: fileUrl || null,
      fileName: fileName || null,
      fileSize: fileSize || null,
      fileMime: fileMime || null,
      replyToId: replyToId || null,
      replyPreview: replyPreview || null,
      reactions: [],
      edited: false,
      deleted: false,
      timestamp: Date.now(),
      pollId: pollId || null,
      location: location || null,
    };
    DB.messages.set(msg.id, msg);
    saveAllData(); // Save after sending group message
    group.members.forEach((uid) => {
      if (uid === socket.userId) return;
      emitToUser(uid, "new_group_message", msg);
      sendPushNotification(uid, {
        title: `${sender?.displayName} in ${group.name}`,
        body: type === "text" ? content || "" : `Sent a ${type}`,
      });
    });
    socket.emit("message_sent", msg);
  });

  socket.on("mark_read", ({ fromUserId }) => {
    if (!socket.userId) return;
    for (const [, m] of DB.messages) {
      if (
        m.fromUserId === fromUserId &&
        m.toUserId === socket.userId &&
        !m.read
      )
        m.read = true;
    }
    saveAllData(); // Save after marking as read
    emitToUser(fromUserId, "messages_read", { byUserId: socket.userId });
  });

  socket.on("delete_message", ({ messageId, toUserId }) => {
    if (!socket.userId) return;
    const msg = DB.messages.get(messageId);
    if (!msg || msg.fromUserId !== socket.userId) return;
    msg.deleted = true;
    msg.content = "";
    msg.fileUrl = null;
    saveAllData(); // Save after deleting message
    emitToUser(toUserId, "message_deleted", { messageId });
  });

  socket.on("typing_start", ({ toUserId }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "user_typing", { userId: socket.userId });
  });
  socket.on("typing_stop", ({ toUserId }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "user_stop_typing", { userId: socket.userId });
  });
  socket.on("group_typing_start", ({ groupId }) => {
    if (!socket.userId) return;
    const group = DB.groups.get(groupId);
    if (!group) return;
    group.members.forEach((uid) => {
      if (uid !== socket.userId)
        emitToUser(uid, "user_typing", { userId: socket.userId, groupId });
    });
  });
  socket.on("group_typing_stop", ({ groupId }) => {
    if (!socket.userId) return;
    const group = DB.groups.get(groupId);
    if (!group) return;
    group.members.forEach((uid) => {
      if (uid !== socket.userId)
        emitToUser(uid, "user_stop_typing", { userId: socket.userId, groupId });
    });
  });

  // 1-on-1 Calls
  socket.on("call_user", ({ toUserId, offer, callId, callType }) => {
    if (!socket.userId) return;
    const caller = DB.users.get(socket.userId);
    emitToUser(toUserId, "incoming_call", {
      callId,
      fromUserId: socket.userId,
      fromUsername: caller?.displayName || "Unknown",
      fromAvatarColor: caller?.avatarColor,
      fromAvatarImg: caller?.avatarImg || null,
      offer,
      callType: callType || "voice",
    });
  });
  socket.on("answer_call", ({ callId, toUserId, answer }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "call_answered", { callId, answer });
  });
  socket.on("reject_call", ({ callId, toUserId }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "call_rejected", { callId });
    const caller = DB.users.get(toUserId);
    addCallHistory(socket.userId, {
      id: callId,
      type: "incoming",
      status: "rejected",
      userId: toUserId,
      userName: caller?.displayName || "Unknown",
      callType: "voice",
      duration: 0,
      timestamp: Date.now(),
    });
    addCallHistory(toUserId, {
      id: callId,
      type: "outgoing",
      status: "rejected",
      userId: socket.userId,
      userName: DB.users.get(socket.userId)?.displayName || "Unknown",
      callType: "voice",
      duration: 0,
      timestamp: Date.now(),
    });
  });
  socket.on("end_call", ({ callId, toUserId, duration, callType }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "call_ended", { callId });
    const otherUser = DB.users.get(toUserId);
    const me = DB.users.get(socket.userId);
    addCallHistory(socket.userId, {
      id: callId,
      type: "outgoing",
      status: "completed",
      callType: callType || "voice",
      userId: toUserId,
      userName: otherUser?.displayName || "Unknown",
      duration: duration || 0,
      timestamp: Date.now(),
    });
    addCallHistory(toUserId, {
      id: callId,
      type: "incoming",
      status: "completed",
      callType: callType || "voice",
      userId: socket.userId,
      userName: me?.displayName || "Unknown",
      duration: duration || 0,
      timestamp: Date.now(),
    });
  });
  socket.on("call_missed", ({ callId, toUserId, callType }) => {
    const otherUser = DB.users.get(toUserId);
    addCallHistory(socket.userId, {
      id: callId,
      type: "outgoing",
      status: "missed",
      callType: callType || "voice",
      userId: toUserId,
      userName: otherUser?.displayName || "Unknown",
      duration: 0,
      timestamp: Date.now(),
    });
    addCallHistory(toUserId, {
      id: callId,
      type: "incoming",
      status: "missed",
      callType: callType || "voice",
      userId: socket.userId,
      userName: DB.users.get(socket.userId)?.displayName || "Unknown",
      duration: 0,
      timestamp: Date.now(),
    });
  });
  socket.on("ice_candidate", ({ toUserId, candidate, callId }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "ice_candidate", {
      candidate,
      callId,
      fromUserId: socket.userId,
    });
  });

  // Group Calls
  socket.on("start_group_call", ({ groupId, callType }) => {
    if (!socket.userId) return;
    const group = DB.groups.get(groupId);
    if (!group || !group.members.includes(socket.userId)) return;
    const callId = `gcall_${Date.now()}`;
    const caller = DB.users.get(socket.userId);
    DB.groupCalls.set(callId, {
      id: callId,
      groupId,
      callType: callType || "voice",
      participants: [socket.userId],
      createdBy: socket.userId,
      startedAt: Date.now(),
    });
    group.members.forEach((uid) => {
      if (uid !== socket.userId) {
        emitToUser(uid, "group_call_invite", {
          callId,
          groupId,
          groupName: group.name,
          callType,
          fromUserId: socket.userId,
          fromUsername: caller?.displayName || "Unknown",
        });
      }
    });
    socket.emit("group_call_started", { callId, groupId });
    socket.join(`gcall_${callId}`);
  });

  socket.on("join_group_call", ({ callId }) => {
    if (!socket.userId) return;
    const call = DB.groupCalls.get(callId);
    if (!call) return;
    if (!call.participants.includes(socket.userId))
      call.participants.push(socket.userId);
    socket.join(`gcall_${callId}`);
    socket
      .to(`gcall_${callId}`)
      .emit("group_call_user_joined", {
        userId: socket.userId,
        userName: DB.users.get(socket.userId)?.displayName || "Unknown",
      });
    socket.emit("group_call_joined", {
      callId,
      participants: call.participants,
    });
  });

  socket.on("group_call_offer", ({ callId, toUserId, offer }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "group_call_offer", {
      callId,
      fromUserId: socket.userId,
      offer,
    });
  });
  socket.on("group_call_answer", ({ callId, toUserId, answer }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "group_call_answer", {
      callId,
      fromUserId: socket.userId,
      answer,
    });
  });
  socket.on("group_call_ice", ({ callId, toUserId, candidate }) => {
    if (!socket.userId) return;
    emitToUser(toUserId, "group_call_ice", {
      callId,
      fromUserId: socket.userId,
      candidate,
    });
  });
  socket.on("leave_group_call", ({ callId }) => {
    if (!socket.userId) return;
    const call = DB.groupCalls.get(callId);
    if (call) {
      call.participants = call.participants.filter((p) => p !== socket.userId);
      if (call.participants.length === 0) DB.groupCalls.delete(callId);
    }
    socket
      .to(`gcall_${callId}`)
      .emit("group_call_user_left", { userId: socket.userId });
    socket.leave(`gcall_${callId}`);
  });

  socket.on("poll_voted", ({ pollId, poll, chatId, groupId }) => {
    if (groupId) {
      const group = DB.groups.get(groupId);
      if (group)
        group.members.forEach((uid) => {
          if (uid !== socket.userId)
            emitToUser(uid, "poll_updated", { pollId, poll });
        });
    } else if (chatId) {
      emitToUser(chatId, "poll_updated", { pollId, poll });
    }
  });

  socket.on("disconnect", () => {
    const userId = socketUserMap.get(socket.id);
    if (userId) {
      socketUserMap.delete(socket.id);
      userSocketMap.delete(userId);
      const user = DB.users.get(userId);
      if (user) user.lastSeen = Date.now();
      broadcastToContacts(userId, "user_offline", {
        userId,
        lastSeen: Date.now(),
      });
    }
  });
});

function emitToUser(userId, event, data) {
  const socketId = userSocketMap.get(userId);
  if (socketId) io.to(socketId).emit(event, data);
}
function broadcastToContacts(userId, event, data) {
  for (const [uid, contactSet] of DB.contacts) {
    if (contactSet.has(userId)) emitToUser(uid, event, data);
  }
}
function getConversation(userA, userB) {
  const msgs = [];
  for (const [, m] of DB.messages) {
    if (
      !m.groupId &&
      ((m.fromUserId === userA && m.toUserId === userB) ||
        (m.fromUserId === userB && m.toUserId === userA))
    )
      msgs.push(m);
  }
  return msgs.sort((a, b) => a.timestamp - b.timestamp);
}
async function sendPushNotification(userId, { title, body }) {
  const sub = DB.pushSubs.get(userId);
  if (!sub) return;
  try {
    await webpush.sendNotification(
      sub,
      JSON.stringify({ title, body, icon: "/icon-192.png" })
    );
  } catch (e) {
    if (e.statusCode === 410) DB.pushSubs.delete(userId);
  }
}

app.get("*", (req, res) => {
  const indexPath = path.join(PUBLIC_DIR, "index.html");
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else
    res
      .status(404)
      .send(`<h2>Place index.html in <code>public/</code> folder.</h2>`);
});

const manifestPath = path.join(PUBLIC_DIR, "manifest.json");
if (!fs.existsSync(manifestPath)) {
  fs.writeFileSync(
    manifestPath,
    JSON.stringify(
      {
        name: "Spark Messenger",
        short_name: "Spark",
        start_url: "/",
        display: "standalone",
        background_color: "#1565C0",
        theme_color: "#1565C0",
        icons: [
          { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
          { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
        ],
      },
      null,
      2
    )
  );
}

const swPath = path.join(PUBLIC_DIR, "sw.js");
if (!fs.existsSync(swPath)) {
  fs.writeFileSync(
    swPath,
    `self.addEventListener('push',function(e){const d=e.data?e.data.json():{};e.waitUntil(self.registration.showNotification(d.title||'Spark',{body:d.body||'New message',icon:d.icon||'/icon-192.png'}));});self.addEventListener('notificationclick',function(e){e.notification.close();e.waitUntil(clients.openWindow('/'));});self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',(e)=>e.waitUntil(clients.claim()));`
  );
}

server.listen(PORT, () => {
  console.log(`\n🚀 Spark Messenger running at http://localhost:${PORT}`);
  console.log(`📁 Public: ${PUBLIC_DIR}`);
  console.log(`📎 Uploads: ${UPLOAD_DIR}`);
  console.log(`💾 Data: ${DATA_DIR}`);
  console.log(`⏰ Auto-save every 30 seconds\n`);
});
