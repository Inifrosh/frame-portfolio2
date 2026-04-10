require('dotenv').config();
const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Inioluwa';

// ── MAILER ───────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendMail(to, subject, html) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS || process.env.EMAIL_USER.includes('your_gmail')) {
    console.log('\n--- EMAIL CONFIG MISSING: MOCKING EMAIL ---');
    console.log(`To: ${to}\nSubject: ${subject}\nBody: ${html}`);
    console.log('-------------------------------------------\n');
    return;
  }
  return transporter.sendMail({ from: `"FRAME" <${process.env.EMAIL_USER}>`, to, subject, html });
}

// ── DATABASE ─────────────────────────────────────
const DB_FILE = path.join(__dirname, 'data.json');
function readDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [], videos: [], sessions: {} };
  try { 
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); 
    if (!data.sessions) data.sessions = {};
    return data;
  }
  catch { return { users: [], videos: [], sessions: {} }; }
}
function writeDB(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

// ── AUTH ─────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex') === hash;
}

function createSession(userId, username, isAdmin) {
  const token = crypto.randomBytes(32).toString('hex');
  const db = readDB();
  db.sessions[token] = { userId, username, isAdmin, createdAt: Date.now() };
  writeDB(db);
  return token;
}

function getSession(token) {
  if (!token) return null;
  const db = readDB();
  const s = db.sessions[token];
  if (!s) return null;
  
  if (Date.now() - s.createdAt > 7 * 24 * 60 * 60 * 1000) { 
    delete db.sessions[token]; 
    writeDB(db);
    return null; 
  }
  return s;
}

function authMiddleware(req, res, next) {
  const s = getSession(req.headers['x-auth-token']);
  if (!s) return res.status(401).json({ error: 'Not authenticated' });
  req.user = s; next();
}

// ── STORAGE ───────────────────────────────────────
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const THUMB_DIR = path.join(__dirname, 'public', 'thumbnails');
[UPLOAD_DIR, THUMB_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, file.fieldname === 'thumbnail' ? THUMB_DIR : UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || (file.fieldname === 'thumbnail' ? '.jpg' : '.mp4');
    cb(null, `${uuidv4()}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'thumbnail') return cb(null, true);
    const allowed = /mp4|mov|avi|mkv|webm|m4v/i;
    if (allowed.test(path.extname(file.originalname))) return cb(null, true);
    cb(new Error('Only video files are allowed'));
  }
});

// ── MIDDLEWARE ────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH ROUTES ───────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'Email, username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  
  const db = readDB();
  if (db.users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase())) return res.status(400).json({ error: 'Email already registered' });
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: 'Username already taken' });
  
  const isAdmin = username.toLowerCase() === ADMIN_USERNAME.toLowerCase();
  const verifyToken = crypto.randomBytes(20).toString('hex');
  
  const user = { 
    id: uuidv4(), 
    email, 
    username, 
    password: hashPassword(password), 
    isAdmin, 
    isVerified: false, 
    verifyToken, 
    createdAt: new Date().toISOString() 
  };
  db.users.push(user); writeDB(db);
  
  const host = req.get('host') || `localhost:${PORT}`;
  const protocol = req.protocol || 'http';
  const verifyUrl = `${protocol}://${host}/verify?token=${verifyToken}`;
  await sendMail(email, 'Verify your FRAME account', `<p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`);
  
  res.json({ success: true, message: 'Account created! Please check your email to verify before logging in.' });
});

app.get('/verify', (req, res) => {
  const { token } = req.query;
  const db = readDB();
  const user = db.users.find(u => u.verifyToken === token);
  if (!user) return res.status(400).send('Invalid or expired verification link.');
  user.isVerified = true;
  user.verifyToken = null;
  writeDB(db);
  res.send('<div style="font-family:monospace;text-align:center;margin-top:50px">Account verified! You can now close this window and log in on the main site.</div>');
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const db = readDB();
  
  const user = db.users.find(u => (u.email && u.email.toLowerCase() === email.toLowerCase()) || u.username.toLowerCase() === email.toLowerCase());
  
  if (!user || !verifyPassword(password, user.password)) return res.status(401).json({ error: 'Invalid email or password' });
  if (user.email && !user.isVerified) return res.status(403).json({ error: 'Please verify your email before logging in.' });
  
  const token = createSession(user.id, user.username, user.isAdmin);
  res.json({ token, username: user.username, userId: user.id, isAdmin: user.isAdmin });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase());
  if (user) {
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExp = Date.now() + 3600000;
    writeDB(db);
    const host = req.get('host') || `localhost:${PORT}`;
    const protocol = req.protocol || 'http';
    const resetUrl = `${protocol}://${host}/?reset=${resetToken}`;
    await sendMail(email, 'FRAME Password Reset', `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`);
  }
  res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { token, password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const db = readDB();
  const user = db.users.find(u => u.resetToken === token && u.resetTokenExp > Date.now());
  if (!user) return res.status(400).json({ error: 'Invalid or expired reset link' });
  
  user.password = hashPassword(password);
  user.resetToken = null;
  user.resetTokenExp = null;
  writeDB(db);
  res.json({ success: true, message: 'Password has been reset. You can now login.' });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) {
    const db = readDB();
    if (db.sessions[token]) {
      delete db.sessions[token];
      writeDB(db);
    }
  }
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  const s = getSession(req.headers['x-auth-token']);
  if (!s) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ username: s.username, userId: s.userId, isAdmin: s.isAdmin });
});

// ── VIDEO ROUTES ──────────────────────────────────

app.get('/api/portfolio', (req, res) => {
  const db = readDB();
  let videos = db.videos.filter(v => v.isPortfolio).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const { category } = req.query;
  if (category && category !== 'all') videos = videos.filter(v => v.category === category);
  res.json(videos.map(v => ({ id: v.id, title: v.title, category: v.category, description: v.description, thumbnail: v.thumbnail, shareId: v.shareId, filename: v.filename, created_at: v.created_at })));
});

app.get('/api/storage', authMiddleware, (req, res) => {
  const db = readDB();
  let videos = db.videos.filter(v => v.userId === req.user.userId && !v.isPortfolio).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const { category } = req.query;
  if (category && category !== 'all') videos = videos.filter(v => v.category === category);
  res.json(videos.map(v => ({ id: v.id, title: v.title, category: v.category, description: v.description, thumbnail: v.thumbnail, shareId: v.shareId, filename: v.filename, size: v.size, created_at: v.created_at })));
});

app.get('/api/share/:shareId', (req, res) => {
  const db = readDB();
  const video = db.videos.find(v => v.shareId === req.params.shareId && v.isPortfolio);
  if (!video) return res.status(404).json({ error: 'Not found' });
  res.json({ id: video.id, title: video.title, category: video.category, description: video.description, thumbnail: video.thumbnail, shareId: video.shareId, filename: video.filename, created_at: video.created_at });
});

app.post('/api/videos', authMiddleware, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]), async (req, res) => {
  const videoFile = req.files?.video?.[0];
  const thumbFile = req.files?.thumbnail?.[0];
  if (!videoFile) return res.status(400).json({ error: 'No video file provided' });
  const { title, category, description } = req.body;
  if (!title || !category) {
    fs.unlinkSync(videoFile.path);
    if (thumbFile) fs.unlinkSync(thumbFile.path);
    return res.status(400).json({ error: 'Title and category required' });
  }
  const id = uuidv4();
  const shareId = uuidv4().replace(/-/g, '').substring(0, 12);
  const entry = {
    id, shareId, title, category,
    description: description || '',
    filename: videoFile.filename,
    thumbnail: thumbFile ? thumbFile.filename : null,
    size: videoFile.size,
    userId: req.user.userId,
    username: req.user.username,
    isPortfolio: req.user.isAdmin,
    created_at: new Date().toISOString()
  };
  const db = readDB();
  db.videos.push(entry); writeDB(db);
  res.json(entry);
});

app.delete('/api/videos/:id', authMiddleware, (req, res) => {
  const db = readDB();
  const idx = db.videos.findIndex(v => v.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (db.videos[idx].userId !== req.user.userId) return res.status(403).json({ error: 'Not your video' });
  
  const video = db.videos[idx];
  [path.join(UPLOAD_DIR, video.filename), video.thumbnail ? path.join(THUMB_DIR, video.thumbnail) : null]
    .filter(Boolean).forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });
  
  db.videos.splice(idx, 1); writeDB(db);
  res.json({ success: true });
});

app.get('/video/:filename', (req, res) => {
  const token = req.headers['x-auth-token'] || req.query.token;
  const session = getSession(token);
  const db = readDB();
  const video = db.videos.find(v => v.filename === req.params.filename);
  
  if (!video) return res.status(404).send('Not found');
  if (!video.isPortfolio) {
    if (!session) return res.status(401).send('Unauthorized');
    if (video.userId !== session.userId) return res.status(403).send('Forbidden');
  }
  const filePath = path.join(UPLOAD_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  
  const stat = fs.statSync(filePath);
  const fileSize = stat.size;
  const range = req.headers.range;
  if (range) {
    const parts = range.replace(/bytes=/, '').split('-');
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
    res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${fileSize}`, 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1, 'Content-Type': 'video/mp4' });
    fs.createReadStream(filePath, { start, end }).pipe(res);
  } else {
    res.writeHead(200, { 'Content-Length': fileSize, 'Content-Type': 'video/mp4' });
    fs.createReadStream(filePath).pipe(res);
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`🎬 FRAME running at http://localhost:${PORT}`));