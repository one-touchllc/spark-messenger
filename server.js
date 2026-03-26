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
// --- NAYA: Passport Modules ---
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" }, maxHttpBufferSize: 1e8 });

app.use(cors());
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(express.static(path.join(__dirname, "public")));
// --- NAYA: Passport Initialize ---
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

// --- UPDATED: Users table with Google Fields ---
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
  -- ... (baaki tables waisi hi rahengi)
`);

// (Note: Baaki tables ka code aapke original code se waisa hi rahega...)
// Yahan space kam hai isliye main sirf badlav wala hissa likh raha hoon.

const JWT_SECRET = process.env.JWT_SECRET || "sparkmessenger_v5_2024";

// --- NAYA: Google Passport Strategy ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://spark-messenger.up.railway.app/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if user exists by Google ID or Email
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
    } catch (err) {
      return done(err, null);
    }
  }
));

// --- NAYA: Google Auth Routes ---
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback", 
  passport.authenticate("google", { session: false, failureRedirect: "/login" }),
  (req, res) => {
    // Generate JWT Token for Google User
    const token = jwt.sign({ id: req.user.id, email: req.user.email }, JWT_SECRET, { expiresIn: "30d" });
    
    // Frontend ko token bhej rahe hain URL ke zariye (aap ise localStorage mein save kar sakte hain)
    res.redirect(`/?token=${token}`);
  }
);

// (Aapka baaki ka sara purana code yahan niche continue hoga: /api/register, /api/login, Socket.io etc.)
// ... 

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Spark Messenger v5 running on port ${PORT}`));
