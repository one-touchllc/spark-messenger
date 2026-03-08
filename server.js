const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" }, maxHttpBufferSize: 1e7 });

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

const JWT_SECRET = "sparkmessenger_secret_2024";

// ── In-memory store ──
const users = new Map();
const messages = new Map();
const rooms = new Map();
const groups = new Map();
const groupMessages = new Map();
const userSockets = new Map();
const activeCalls = new Map();
const contacts = new Map();
const blocked = new Map();
const statuses = new Map();
const pinnedChats = new Map();
const archivedChats = new Map();

function getRoomId(a, b) { return [a, b].sort().join("_"); }
function getOrCreateRoom(a, b) {
  const id = getRoomId(a, b);
  if (!rooms.has(id)) { rooms.set(id, { id, participants: [a, b] }); messages.set(id, []); }
  return id;
}
function authMW(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

// ── AUTH ──
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Required" });
  for (const u of users.values())
    if (u.username.toLowerCase() === username.toLowerCase())
      return res.status(409).json({ error: "Username already taken" });
  const id = uuidv4();
  const colors = ["#25D366","#128C7E","#075E54","#34B7F1","#FF6B6B","#A29BFE","#FD79A8","#FDCB6E","#6C5CE7","#00B894"];
  const user = {
    id, username,
    password: await bcrypt.hash(password, 10),
    avatarColor: colors[Math.floor(Math.random() * colors.length)],
    avatarImg: null,
    status: "Hey there! I am using Spark Messenger.",
    about: "",
    language: "en",
    createdAt: Date.now()
  };
  users.set(id, user);
  contacts.set(id, new Set());
  blocked.set(id, new Set());
  statuses.set(id, []);
  pinnedChats.set(id, new Set());
  archivedChats.set(id, new Set());
  const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: safeUser(user) });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  let found = null;
  for (const u of users.values()) if (u.username.toLowerCase() === username.toLowerCase()) { found = u; break; }
  if (!found || !(await bcrypt.compare(password, found.password)))
    return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: found.id, username: found.username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: safeUser(found) });
});

function safeUser(u) {
  return { id: u.id, username: u.username, avatarColor: u.avatarColor, avatarImg: u.avatarImg, status: u.status, about: u.about, language: u.language };
}

// ── CONTACTS ──
app.get("/api/contacts", authMW, (req, res) => {
  const myContacts = contacts.get(req.user.id) || new Set();
  const list = [];
  for (const cId of myContacts) {
    const u = users.get(cId);
    if (u) list.push({ ...safeUser(u), online: userSockets.has(u.id) });
  }
  res.json(list);
});

app.post("/api/contacts/add", authMW, (req, res) => {
  const { username } = req.body;
  let found = null;
  for (const u of users.values()) if (u.username.toLowerCase() === username.toLowerCase()) { found = u; break; }
  if (!found) return res.status(404).json({ error: "User not found" });
  if (found.id === req.user.id) return res.status(400).json({ error: "Cannot add yourself" });
  const myContacts = contacts.get(req.user.id) || new Set();
  myContacts.add(found.id);
  contacts.set(req.user.id, myContacts);
  res.json({ user: { ...safeUser(found), online: userSockets.has(found.id) } });
});

app.delete("/api/contacts/:id", authMW, (req, res) => {
  const myContacts = contacts.get(req.user.id) || new Set();
  myContacts.delete(req.params.id);
  res.json({ ok: true });
});

// ── BLOCK ──
app.post("/api/block/:id", authMW, (req, res) => {
  const bl = blocked.get(req.user.id) || new Set();
  bl.add(req.params.id); blocked.set(req.user.id, bl);
  res.json({ ok: true });
});
app.post("/api/unblock/:id", authMW, (req, res) => {
  const bl = blocked.get(req.user.id) || new Set();
  bl.delete(req.params.id); blocked.set(req.user.id, bl);
  res.json({ ok: true });
});
app.get("/api/blocked", authMW, (req, res) => {
  const bl = blocked.get(req.user.id) || new Set();
  const list = [];
  for (const id of bl) { const u = users.get(id); if (u) list.push(safeUser(u)); }
  res.json(list);
});

// ── PROFILE ──
app.put("/api/profile", authMW, (req, res) => {
  const u = users.get(req.user.id);
  if (!u) return res.status(404).json({ error: "Not found" });
  if (req.body.status !== undefined) u.status = req.body.status;
  if (req.body.about !== undefined) u.about = req.body.about;
  if (req.body.avatarImg !== undefined) u.avatarImg = req.body.avatarImg;
  if (req.body.language !== undefined) u.language = req.body.language;
  res.json(safeUser(u));
});

// ── MESSAGES ──
app.get("/api/messages/:userId", authMW, (req, res) => {
  const bl = blocked.get(req.user.id) || new Set();
  if (bl.has(req.params.userId)) return res.json([]);
  const roomId = getRoomId(req.user.id, req.params.userId);
  res.json(messages.get(roomId) || []);
});

// ── PIN / ARCHIVE ──
app.post("/api/pin/:chatId", authMW, (req, res) => {
  const pins = pinnedChats.get(req.user.id) || new Set();
  pins.add(req.params.chatId); pinnedChats.set(req.user.id, pins);
  res.json({ ok: true });
});
app.post("/api/unpin/:chatId", authMW, (req, res) => {
  const pins = pinnedChats.get(req.user.id) || new Set();
  pins.delete(req.params.chatId); pinnedChats.set(req.user.id, pins);
  res.json({ ok: true });
});
app.post("/api/archive/:chatId", authMW, (req, res) => {
  const arch = archivedChats.get(req.user.id) || new Set();
  arch.add(req.params.chatId); archivedChats.set(req.user.id, arch);
  res.json({ ok: true });
});
app.post("/api/unarchive/:chatId", authMW, (req, res) => {
  const arch = archivedChats.get(req.user.id) || new Set();
  arch.delete(req.params.chatId); archivedChats.set(req.user.id, arch);
  res.json({ ok: true });
});
app.get("/api/meta", authMW, (req, res) => {
  res.json({
    pinned: [...(pinnedChats.get(req.user.id) || [])],
    archived: [...(archivedChats.get(req.user.id) || [])]
  });
});

// ── STATUS ──
app.get("/api/statuses", authMW, (req, res) => {
  const myContacts = contacts.get(req.user.id) || new Set();
  const list = [];
  const addStatus = (uid) => {
    const u = users.get(uid);
    const sts = statuses.get(uid) || [];
    const recent = sts.filter(s => Date.now() - s.timestamp < 86400000);
    if (u) list.push({ user: safeUser(u), statuses: recent, isMe: uid === req.user.id });
  };
  addStatus(req.user.id);
  for (const cId of myContacts) addStatus(cId);
  res.json(list);
});
app.post("/api/status", authMW, (req, res) => {
  const { content, type } = req.body;
  const sts = statuses.get(req.user.id) || [];
  const item = { id: uuidv4(), content, type: type || "text", timestamp: Date.now() };
  sts.push(item);
  statuses.set(req.user.id, sts);
  io.emit("new_status", { userId: req.user.id });
  res.json(item);
});

// ── GROUPS ──
app.post("/api/groups", authMW, (req, res) => {
  const { name, memberIds } = req.body;
  if (!name || !memberIds?.length) return res.status(400).json({ error: "Required" });
  const id = uuidv4();
  const group = { id, name, adminId: req.user.id, members: [req.user.id, ...memberIds], avatarColor: "#25D366", avatarImg: null, description: "", createdAt: Date.now() };
  groups.set(id, group);
  groupMessages.set(id, []);
  for (const mId of group.members) {
    if (userSockets.has(mId)) io.to(`user_${mId}`).emit("added_to_group", group);
  }
  res.json(group);
});

app.get("/api/groups", authMW, (req, res) => {
  const list = [];
  for (const g of groups.values()) if (g.members.includes(req.user.id)) list.push(g);
  res.json(list);
});

app.get("/api/groups/:id/messages", authMW, (req, res) => {
  const g = groups.get(req.params.id);
  if (!g || !g.members.includes(req.user.id)) return res.status(403).json({ error: "Forbidden" });
  res.json(groupMessages.get(req.params.id) || []);
});

app.post("/api/groups/:id/leave", authMW, (req, res) => {
  const g = groups.get(req.params.id);
  if (!g) return res.status(404).json({ error: "Not found" });
  g.members = g.members.filter(m => m !== req.user.id);
  if (g.members.length === 0) { groups.delete(req.params.id); }
  else if (g.adminId === req.user.id) { g.adminId = g.members[0]; }
  io.emit("group_updated", g);
  res.json({ ok: true });
});

app.put("/api/groups/:id", authMW, (req, res) => {
  const g = groups.get(req.params.id);
  if (!g || g.adminId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  if (req.body.name) g.name = req.body.name;
  if (req.body.description !== undefined) g.description = req.body.description;
  if (req.body.avatarImg !== undefined) g.avatarImg = req.body.avatarImg;
  io.emit("group_updated", g);
  res.json(g);
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ── SOCKET.IO ──
io.on("connection", (socket) => {
  socket.on("authenticate", (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.userId = decoded.id;
      userSockets.set(decoded.id, socket.id);
      socket.join(`user_${decoded.id}`);
      for (const g of groups.values()) if (g.members.includes(decoded.id)) socket.join(`group_${g.id}`);
      io.emit("user_online", { userId: decoded.id });
      socket.emit("authenticated", { userId: decoded.id });
    } catch { socket.emit("auth_error"); }
  });

  socket.on("send_message", ({ toUserId, content, type, mediaData, mediaName }) => {
    if (!socket.userId) return;
    const bl = blocked.get(toUserId) || new Set();
    if (bl.has(socket.userId)) return;
    const roomId = getOrCreateRoom(socket.userId, toUserId);
    const msg = { id: uuidv4(), roomId, fromUserId: socket.userId, toUserId, content: content || "", type: type || "text", mediaData: mediaData || null, mediaName: mediaName || null, timestamp: Date.now(), read: false, deleted: false };
    messages.get(roomId).push(msg);
    io.to(`user_${toUserId}`).emit("new_message", msg);
    socket.emit("message_sent", msg);
  });

  socket.on("send_group_message", ({ groupId, content, type, mediaData, mediaName }) => {
    if (!socket.userId) return;
    const g = groups.get(groupId);
    if (!g || !g.members.includes(socket.userId)) return;
    const sender = users.get(socket.userId);
    const msg = { id: uuidv4(), groupId, fromUserId: socket.userId, fromUsername: sender?.username, fromAvatarColor: sender?.avatarColor, content: content || "", type: type || "text", mediaData: mediaData || null, mediaName: mediaName || null, timestamp: Date.now(), readBy: [socket.userId] };
    groupMessages.get(groupId).push(msg);
    io.to(`group_${groupId}`).emit("new_group_message", msg);
  });

  socket.on("mark_read", ({ fromUserId }) => {
    if (!socket.userId) return;
    const roomId = getRoomId(socket.userId, fromUserId);
    (messages.get(roomId) || []).forEach(m => { if (m.toUserId === socket.userId) m.read = true; });
    io.to(`user_${fromUserId}`).emit("messages_read", { byUserId: socket.userId });
  });

  socket.on("typing_start", ({ toUserId }) => io.to(`user_${toUserId}`).emit("user_typing", { userId: socket.userId }));
  socket.on("typing_stop", ({ toUserId }) => io.to(`user_${toUserId}`).emit("user_stop_typing", { userId: socket.userId }));
  socket.on("group_typing_start", ({ groupId }) => socket.to(`group_${groupId}`).emit("group_user_typing", { userId: socket.userId, groupId }));
  socket.on("group_typing_stop", ({ groupId }) => socket.to(`group_${groupId}`).emit("group_user_stop_typing", { userId: socket.userId, groupId }));

  socket.on("delete_message", ({ messageId, toUserId }) => {
    const roomId = getRoomId(socket.userId, toUserId);
    const msgs = messages.get(roomId) || [];
    const msg = msgs.find(m => m.id === messageId && m.fromUserId === socket.userId);
    if (msg) { msg.deleted = true; msg.content = "This message was deleted"; msg.mediaData = null; }
    io.to(`user_${toUserId}`).emit("message_deleted", { messageId });
    socket.emit("message_deleted", { messageId });
  });

  // WebRTC
  socket.on("call_user", ({ toUserId, offer, callId, callType }) => {
    const caller = users.get(socket.userId);
    const cId = callId || uuidv4();
    activeCalls.set(cId, { id: cId, callerId: socket.userId, calleeId: toUserId, status: "ringing", type: callType || "voice" });
    io.to(`user_${toUserId}`).emit("incoming_call", { callId: cId, fromUserId: socket.userId, fromUsername: caller?.username, fromAvatarColor: caller?.avatarColor, fromAvatarImg: caller?.avatarImg, offer, callType: callType || "voice" });
    socket.emit("call_initiated", { callId: cId });
  });
  socket.on("answer_call", ({ callId, toUserId, answer }) => {
    const call = activeCalls.get(callId);
    if (call) call.status = "active";
    io.to(`user_${toUserId}`).emit("call_answered", { callId, answer });
  });
  socket.on("reject_call", ({ callId, toUserId }) => {
    activeCalls.delete(callId);
    io.to(`user_${toUserId}`).emit("call_rejected", { callId });
  });
  socket.on("end_call", ({ callId, toUserId }) => {
    activeCalls.delete(callId);
    io.to(`user_${toUserId}`).emit("call_ended", { callId });
  });
  socket.on("ice_candidate", ({ toUserId, candidate, callId }) => {
    io.to(`user_${toUserId}`).emit("ice_candidate", { candidate, callId, fromUserId: socket.userId });
  });

  socket.on("disconnect", () => {
    if (socket.userId) {
      userSockets.delete(socket.userId);
      io.emit("user_offline", { userId: socket.userId });
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Spark Messenger running on port ${PORT}`));
