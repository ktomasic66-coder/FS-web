require('dotenv').config();

let mainGuild = null;

const express = require('express');
const mongoose = require('mongoose');

// ===== MONGODB CONNECTION =====
const MONGO_URI = process.env.MONGO_URI || 'mongodb://mongo:OOvotyonHPYWjWuBLnbiBSUskMFrATIU@caboose.proxy.rlwy.net:40886';
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected (Slavonska Ravnica)'))
  .catch(err => console.log('MongoDB connection error (Slavonska Ravnica):', err));

// ===== FARM MODEL (Slavonska Ravnica) =====
const farmSchema = new mongoose.Schema({
  userId: String,
  farmName: String,
  balance: Number,
  animals: [String],
  storage: [String],
  equipment: [String],
  productions: [String],
  cropCalendar: [String],
});
const Farm = mongoose.models.Farm || mongoose.model('Farm', farmSchema);

const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { getPlayerStats } = require('./player');
let mysql = null;
try {
  mysql = require('mysql2/promise');
} catch {
  mysql = null;
}

const { Client, GatewayIntentBits } = require('discord.js');

const app = express();
let dbPool = null;
let useMySql = false;

/* ================= PATHS / FILES ================= */

const DATA_FILE = path.join(__dirname, 'gallery.json');
const NEWS_FILE = path.join(__dirname, 'news.json');
const RULES_FILE = path.join(__dirname, 'rules.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
const LOG_FILE = path.join(__dirname, 'admin-logs.json');

const uploadPath = path.join(__dirname, 'public/uploads');
const backupDir = path.join(__dirname, 'backups');
const SESSION_FILE = path.join(__dirname, 'sessions.json');

/* funkcje loga */

function loadLogs() {
  if (!fs.existsSync(LOG_FILE)) return [];
  return JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
}

function saveLogs(data) {
  fs.writeFileSync(LOG_FILE, JSON.stringify(data, null, 2));
}

function addLog(action, admin, details) {
  const logs = loadLogs();

  logs.unshift({
    id: Date.now(),
    action,
    admin,
    details,
    date: new Date().toLocaleString()
  });

  saveLogs(logs);
}

/* ================= ENV ================= */

const GUILD_ID = process.env.GUILD_ID;
const PLAYER_ROLE_ID = process.env.PLAYER_ROLE_ID; // npr Player role
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;   // npr Admin role
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

/* ===== GLOBAL ROLE IDS (za admin panel + badge) ===== */

const ROLE_IDS = {
  OWNER: '1238860450528235550',
  CO_OWNER: '1449551727010254858',
  ADMIN: '863814372610146314',
  PLAYER: '1238209853009297560',
  MEMBER: '1238854428136571000',
};

/* ================= DISCORD BOT ================= */

const discordClient = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers],
});

let discordMemberCount = 0;

discordClient.once('clientReady', async () => {
  console.log(`🤖 Bot prijavljen kao ${discordClient.user.tag}`);

  try {
    mainGuild = await discordClient.guilds.fetch(GUILD_ID);
    await mainGuild.members.fetch(); // cache members
    discordMemberCount = mainGuild.memberCount;

    console.log('📊 Discord članovi:', discordMemberCount);
  } catch (err) {
    console.log('❌ Guild error:', err.message);
  }
});

discordClient.login(BOT_TOKEN);

/* ================= PASSPORT ================= */

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
      scope: ['identify', 'guilds', 'guilds.members.read'],
    },
    (accessToken, refreshToken, profile, done) => {
      process.nextTick(() => done(null, profile));
    }
  )
);

/* ================= HELPERS (FILES) ================= */

function readJsonSafe(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonSafe(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function readSessionMap() {
  return readJsonSafe(SESSION_FILE, {});
}

function writeSessionMap(data) {
  writeJsonSafe(SESSION_FILE, data);
}

class FileSessionStore extends session.Store {
  get(sid, callback) {
    try {
      const map = readSessionMap();
      const raw = map[sid];
      callback(null, raw ? JSON.parse(raw) : null);
    } catch (err) {
      callback(err);
    }
  }

  set(sid, sess, callback) {
    try {
      const map = readSessionMap();
      map[sid] = JSON.stringify(sess);
      writeSessionMap(map);
      callback && callback(null);
    } catch (err) {
      callback && callback(err);
    }
  }

  destroy(sid, callback) {
    try {
      const map = readSessionMap();
      delete map[sid];
      writeSessionMap(map);
      callback && callback(null);
    } catch (err) {
      callback && callback(err);
    }
  }

  touch(sid, sess, callback) {
    this.set(sid, sess, callback);
  }
}

/* ----- Gallery ----- */
async function initMySql() {
  if (!mysql) {
    console.log('MySQL driver nije dostupan, fallback na JSON.');
    return;
  }

  const mysqlUrl = process.env.MYSQL_URL || process.env.DATABASE_URL || '';
  const mysqlHost = process.env.MYSQLHOST || '';
  const mysqlPort = Number(process.env.MYSQLPORT || 3306);
  const mysqlUser = process.env.MYSQLUSER || '';
  const mysqlPassword = process.env.MYSQLPASSWORD || '';
  const mysqlDatabase = process.env.MYSQLDATABASE || '';

  if (!mysqlUrl && !mysqlHost) {
    console.log('MYSQL_URL/MYSQLHOST nije postavljen, fallback na JSON.');
    return;
  }

  try {
    if (mysqlUrl) {
      dbPool = mysql.createPool(mysqlUrl);
    } else {
      dbPool = mysql.createPool({
        host: mysqlHost,
        port: mysqlPort,
        user: mysqlUser,
        password: mysqlPassword,
        database: mysqlDatabase,
        connectionLimit: 8,
        waitForConnections: true,
        queueLimit: 0,
      });
    }

    await dbPool.query('SELECT 1');

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS news (
        id BIGINT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        author VARCHAR(120) NOT NULL,
        date_text VARCHAR(120) NOT NULL
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS gallery_images (
        filename VARCHAR(255) PRIMARY KEY,
        uploader_id VARCHAR(64) NOT NULL,
        uploader_name VARCHAR(120) NOT NULL,
        uploader_avatar VARCHAR(255) DEFAULT NULL
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS gallery_comments (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        image_filename VARCHAR(255) NOT NULL,
        user_name VARCHAR(120) NOT NULL,
        text TEXT NOT NULL,
        date_text VARCHAR(120) NOT NULL,
        CONSTRAINT fk_gallery_image
          FOREIGN KEY (image_filename) REFERENCES gallery_images(filename)
          ON DELETE CASCADE
      )
    `);

    useMySql = true;
    await migrateNewsAndGalleryIfNeeded();
    console.log('MySQL storage aktivan (news + gallery).');
  } catch (err) {
    console.log('MySQL init error, fallback na JSON:', err.message);
    useMySql = false;
    dbPool = null;
  }
}

async function migrateNewsAndGalleryIfNeeded() {
  if (!useMySql || !dbPool) return;

  const [newsCountRows] = await dbPool.query('SELECT COUNT(*) AS c FROM news');
  if (newsCountRows[0].c === 0) {
    const newsFromFile = readJsonSafe(NEWS_FILE, []);
    for (const post of newsFromFile) {
      await dbPool.query(
        'INSERT INTO news (id, title, content, author, date_text) VALUES (?, ?, ?, ?, ?)',
        [
          Number(post.id) || Date.now(),
          String(post.title || ''),
          String(post.content || ''),
          String(post.author || 'unknown'),
          String(post.date || ''),
        ]
      );
    }
  }

  const [galleryCountRows] = await dbPool.query('SELECT COUNT(*) AS c FROM gallery_images');
  if (galleryCountRows[0].c === 0) {
    const galleryFromFile = readJsonSafe(DATA_FILE, []);
    for (const image of galleryFromFile) {
      await dbPool.query(
        'INSERT INTO gallery_images (filename, uploader_id, uploader_name, uploader_avatar) VALUES (?, ?, ?, ?)',
        [
          String(image.filename || ''),
          String(image.uploaderId || ''),
          String(image.uploaderName || ''),
          image.uploaderAvatar ? String(image.uploaderAvatar) : null,
        ]
      );

      const comments = Array.isArray(image.comments) ? image.comments : [];
      for (const comment of comments) {
        await dbPool.query(
          'INSERT INTO gallery_comments (image_filename, user_name, text, date_text) VALUES (?, ?, ?, ?)',
          [
            String(image.filename || ''),
            String(comment.user || ''),
            String(comment.text || ''),
            String(comment.date || ''),
          ]
        );
      }
    }
  }
}

async function loadGallery() {
  if (!useMySql || !dbPool) {
    const data = readJsonSafe(DATA_FILE, []);
    return data.filter((img) => {
      const imagePath = path.join(__dirname, 'public/uploads', img.filename);
      return fs.existsSync(imagePath);
    });
  }

  const [imageRows] = await dbPool.query(
    'SELECT filename, uploader_id, uploader_name, uploader_avatar FROM gallery_images'
  );
  const [commentRows] = await dbPool.query(
    'SELECT image_filename, user_name, text, date_text FROM gallery_comments ORDER BY id ASC'
  );

  const commentsByImage = new Map();
  for (const row of commentRows) {
    const existing = commentsByImage.get(row.image_filename) || [];
    existing.push({
      user: row.user_name,
      text: row.text,
      date: row.date_text,
    });
    commentsByImage.set(row.image_filename, existing);
  }

  return imageRows
    .map((row) => ({
      filename: row.filename,
      uploaderId: row.uploader_id,
      uploaderName: row.uploader_name,
      uploaderAvatar: row.uploader_avatar,
      comments: commentsByImage.get(row.filename) || [],
    }))
    .filter((img) => fs.existsSync(path.join(__dirname, 'public/uploads', img.filename)));
}

async function addGalleryImage(item) {
  if (!useMySql || !dbPool) {
    const gallery = readJsonSafe(DATA_FILE, []);
    gallery.push(item);
    writeJsonSafe(DATA_FILE, gallery);
    return;
  }

  await dbPool.query(
    `INSERT INTO gallery_images (filename, uploader_id, uploader_name, uploader_avatar)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       uploader_id = VALUES(uploader_id),
       uploader_name = VALUES(uploader_name),
       uploader_avatar = VALUES(uploader_avatar)`,
    [item.filename, item.uploaderId, item.uploaderName, item.uploaderAvatar || null]
  );
}

async function addGalleryComment(filename, comment) {
  if (!useMySql || !dbPool) {
    const gallery = readJsonSafe(DATA_FILE, []);
    const image = gallery.find((img) => img.filename === filename);
    if (!image) return false;
    image.comments.push(comment);
    writeJsonSafe(DATA_FILE, gallery);
    return true;
  }

  const [rows] = await dbPool.query('SELECT filename FROM gallery_images WHERE filename = ?', [filename]);
  if (!rows.length) return false;

  await dbPool.query(
    'INSERT INTO gallery_comments (image_filename, user_name, text, date_text) VALUES (?, ?, ?, ?)',
    [filename, comment.user, comment.text, comment.date]
  );
  return true;
}

async function deleteGalleryImageByFilename(filename) {
  if (!useMySql || !dbPool) {
    let gallery = readJsonSafe(DATA_FILE, []);
    gallery = gallery.filter((img) => img.filename !== filename);
    writeJsonSafe(DATA_FILE, gallery);
    return;
  }
  // Brisi komentare eksplicitno pa sliku (radi i ako FK cascade nije aktivan).
  await dbPool.query('DELETE FROM gallery_comments WHERE image_filename = ?', [filename]);
  await dbPool.query('DELETE FROM gallery_images WHERE filename = ?', [filename]);
}

/* ----- News ----- */

async function loadNews() {
  if (!useMySql || !dbPool) {
    return readJsonSafe(NEWS_FILE, []);
  }

  const [rows] = await dbPool.query(
    'SELECT id, title, content, author, date_text AS date FROM news ORDER BY id DESC'
  );
  return rows;
}

async function addNews(item) {
  if (!useMySql || !dbPool) {
    const news = readJsonSafe(NEWS_FILE, []);
    news.unshift(item);
    writeJsonSafe(NEWS_FILE, news);
    return;
  }

  await dbPool.query(
    'INSERT INTO news (id, title, content, author, date_text) VALUES (?, ?, ?, ?, ?)',
    [item.id, item.title, item.content, item.author, item.date]
  );
}

async function deleteNewsById(id) {
  if (!useMySql || !dbPool) {
    let news = readJsonSafe(NEWS_FILE, []);
    const before = news.length;
    news = news.filter((n) => Number(n.id) !== Number(id));
    writeJsonSafe(NEWS_FILE, news);
    return before !== news.length;
  }

  const [result] = await dbPool.query('DELETE FROM news WHERE id = ?', [id]);
  return result.affectedRows > 0;
}

/* ----- Rules ----- */

function loadRules() {
  return readJsonSafe(RULES_FILE, { content: '' });
}

function saveRules(data) {
  writeJsonSafe(RULES_FILE, data);
}

/* ----- Logs ----- */

function logAction(action, adminUser) {
  const logs = readJsonSafe(LOG_FILE, []);
  logs.unshift({
    action,
    admin: adminUser,
    date: new Date().toLocaleString(),
  });
  writeJsonSafe(LOG_FILE, logs);
}

/* ----- Blacklist ----- */

function loadBlacklist() {
  return readJsonSafe(BLACKLIST_FILE, []);
}

function isBlacklisted(userId) {
  return loadBlacklist().includes(userId);
}

function addToBlacklist(userId) {
  const list = loadBlacklist();
  if (!list.includes(userId)) list.push(userId);
  writeJsonSafe(BLACKLIST_FILE, list);
}

function removeFromBlacklist(userId) {
  let list = loadBlacklist();
  list = list.filter((id) => id !== userId);
  writeJsonSafe(BLACKLIST_FILE, list);
}

/* ----- Backup ----- */

function backupGallery() {
  if (useMySql) return;
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

  const fileName = `backup-${Date.now()}.json`;
  if (!fs.existsSync(DATA_FILE)) writeJsonSafe(DATA_FILE, []);

  fs.copyFileSync(DATA_FILE, path.join(backupDir, fileName));
}

/* ================= ROLES (DISCORD) ================= */

async function getMemberRoles(userId) {
  try {
    if (!mainGuild) return [];

    const member = await mainGuild.members.fetch(userId);

    const roles = member.roles.cache
      .filter((role) => role.name !== '@everyone')
      .map((role) => ({
        id: role.id,
        name: role.name,
        color: role.hexColor && role.hexColor !== '#000000' ? role.hexColor : '#444',
      }));

    console.log('USER ROLES:', roles);
    return roles;
  } catch (err) {
    console.log('ROLE CHECK ERROR:', err.message);
    return [];
  }
}

function hasAnyRole(user, roleIds) {
  const roles = user?.roles || []; // objekti {id,name,color}
  return roles.some((r) => roleIds.includes(r.id));
}

function isGalleryAdminByRoles(roles) {
  const ids = (roles || []).map((r) => r.id);
  const adminIds = [ADMIN_ROLE_ID, ROLE_IDS.ADMIN, ROLE_IDS.CO_OWNER, ROLE_IDS.OWNER].filter(Boolean);
  return ids.some((id) => adminIds.includes(id));
}

function canUploadWithRoles(user, roles) {
  const roleIds = (roles || []).map((r) => r.id);
  const uploadAllowedRoleIds = [
    PLAYER_ROLE_ID,
    ADMIN_ROLE_ID,
    ROLE_IDS.PLAYER,
    ROLE_IDS.ADMIN,
    ROLE_IDS.CO_OWNER,
    ROLE_IDS.OWNER,
  ].filter(Boolean);

  // De-dup i provjera
  return roleIds.some((id) => uploadAllowedRoleIds.includes(id));
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/');

  const ok = hasAnyRole(req.user, [ROLE_IDS.OWNER, ROLE_IDS.CO_OWNER, ROLE_IDS.ADMIN]);
  if (!ok) return res.redirect('/no-permission');

  next();
}

function requireRole(roleId) {
  return (req, res, next) => {
    if (!req.user) return res.redirect('/no-permission');

    const hasRole = (req.user.roles || []).some((r) => r.id === roleId);
    if (!hasRole) return res.redirect('/no-permission');

    next();
  };
}

/* ================= MULTER ================= */

if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, { recursive: true });
}

const storage = multer.diskStorage({
  destination: uploadPath,
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});

const upload = multer({ storage });

/* ================= EXPRESS ================= */

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('trust proxy', 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new FileSessionStore(),
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* ================= ROUTES ================= */

app.get('/', async (req, res) => {
  const news = await loadNews();
  res.render('index', { user: req.user, news });
});

app.get('/no-permission', (req, res) => {
  res.render('no-permission', { user: req.user });
});

/* ===== PROFILE ===== */

app.get('/profile', (req, res) => {
  if (!req.user) return res.redirect('/');

  const userRoles = req.user.roles || [];

  const isAdmin = userRoles.some((role) =>
    [ROLE_IDS.ADMIN, ROLE_IDS.OWNER, ROLE_IDS.CO_OWNER].includes(role.id)
  );

  const isPlayer = userRoles.some((role) => role.id === ROLE_IDS.PLAYER);

  res.render('profile', {
    user: req.user,
    isAdmin,
    isPlayer,
    roles: userRoles,
  });
});

/* ===== ADMIN PANEL ===== */

app.get('/admin', requireAdmin, async (req, res) => {

  const logs = loadLogs();
  const news = await loadNews();
  const images = await loadGallery();

  res.render('admin', {
    user: req.user,
    logs: logs,
    news: news,                   // ⬅️ OVO MORA BITI POSLANO
    discordMembers: discordMemberCount,
    imagesCount: images.length,
    newsCount: news.length
  });

});

/* ===== ADMIN: NEWS ===== */

app.post('/admin/news', requireAdmin, async (req, res) => {
  const title = (req.body.title || '').trim();
  const content = (req.body.content || '').trim();

  if (!title || !content) return res.redirect('/admin');

  await addNews({
    id: Date.now(),
    title,
    content,
    date: new Date().toLocaleString(),
    author: req.user.username,
  });

  logAction(`News objava dodana: "${title}"`, req.user.username);
  res.redirect('/admin');
});

app.post('/admin/news/delete/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const deleted = await deleteNewsById(id);
  if (deleted) logAction(`News obrisan (id=${id})`, req.user.username);
  res.redirect('/admin');
});

/* ===== PRAVILA ===== */

app.get('/pravila', (req, res) => {
  const rules = loadRules();
  res.render('pravila', { user: req.user, rules });
});

app.post('/admin/rules', requireAdmin, (req, res) => {
  const content = req.body.content || '';
  saveRules({ content });

  logAction('Pravila uređena', req.user.username);
  res.redirect('/admin');
});

/* ===== ADMIN: BLACKLIST ===== */

app.post('/admin/blacklist/add', requireAdmin, (req, res) => {
  const userId = (req.body.userId || '').trim();
  if (!userId) return res.redirect('/admin');

  addToBlacklist(userId);
  logAction(`Blacklist ADD: ${userId}`, req.user.username);
  res.redirect('/admin');
});

app.post('/admin/blacklist/remove', requireAdmin, (req, res) => {
  const userId = (req.body.userId || '').trim();
  if (!userId) return res.redirect('/admin');

  removeFromBlacklist(userId);
  logAction(`Blacklist REMOVE: ${userId}`, req.user.username);
  res.redirect('/admin');
});

/* ===== STATISTIKA (G-Portal) ===== */

app.get('/statistika', async (req, res) => {
  const playerStats = await getPlayerStats();

  const stats = {
    serverStatus: playerStats.serverStatus,
    playersOnline: playerStats.playersOnline,
    maxPlayers: playerStats.maxPlayers,
    discordMembers: discordMemberCount,
  };

  res.render('statistika', { user: req.user, stats });
});

/* ===== GALERIJA ===== */

app.get('/moja-farma', async (req, res) => {
  let farm = null;
  if (req.user) {
    farm = await Farm.findOne({ userId: req.user.id });
  }
  res.render('moja-farma', { user: req.user, farm });
});

app.get('/galerija', async (req, res) => {
  let roles = [];
  let canUpload = false;
  let isAdmin = false;

  if (req.user) {
    roles = req.user.roles?.length ? req.user.roles : await getMemberRoles(req.user.id);
    canUpload = canUploadWithRoles(req.user, roles);
    isAdmin = isGalleryAdminByRoles(roles);
  }

  const gallery = await loadGallery();

  res.render('galerija', {
    user: req.user,
    gallery,
    canUpload,
    isAdmin,
  });
});

/* ===== UPLOAD (PLAYER+) ===== */

app.post('/upload', async (req, res) => {
  if (!req.user) return res.redirect('/');

  if (isBlacklisted(req.user.id)) {
    return res.send('Blokiran si za upload.');
  }

  const roles = req.user.roles?.length ? req.user.roles : await getMemberRoles(req.user.id);
  const canUpload = canUploadWithRoles(req.user, roles);

  if (!canUpload) return res.redirect('/no-permission');

  upload.single('image')(req, res, async function (err) {
    if (err) return res.send('Greška.');
    try {
      await addGalleryImage({
        filename: req.file.filename,
        uploaderId: req.user.id,
        uploaderName: req.user.username,
        uploaderAvatar: req.user.avatar,
      });
      return res.redirect('/galerija');
    } catch (e) {
      console.log('UPLOAD IMAGE ERROR:', e.message);
      return res.redirect('/galerija');
    }
  });
});

/* ===== KOMENTAR (basic anti-spam) ===== */

function sanitizeComment(text) {
  const t = String(text || '').slice(0, 300); // max 300 znakova
  // osnovno “čišćenje” (nije savršeno, ali je ok za start)
  return t.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

app.post('/comment/:image', async (req, res) => {
  if (!req.user) return res.redirect('/');

  if (isBlacklisted(req.user.id)) {
    return res.send('Blokiran si za komentare.');
  }

  const text = sanitizeComment(req.body.comment);

  if (!text.trim()) return res.redirect('/galerija');
  const added = await addGalleryComment(req.params.image, {
    user: req.user.username,
    text,
    date: new Date().toLocaleString(),
  });
  if (!added) return res.redirect('/galerija');
  res.redirect('/galerija');
});

/* ===== DELETE (ADMIN+) ===== */

async function handleDeleteImage(req, res, filenameRaw) {
  try {
    if (!req.user) return res.redirect('/');

    const roles = req.user.roles?.length ? req.user.roles : await getMemberRoles(req.user.id);
    const isAdmin = isGalleryAdminByRoles(roles);

    if (!isAdmin) return res.redirect('/no-permission');

    const filename = String(filenameRaw || '').trim();
    if (!filename) return res.redirect('/galerija');

    const imagePath = path.join(__dirname, 'public/uploads', filename);

    // backup prije brisanja
    backupGallery();

    if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);

    await deleteGalleryImageByFilename(filename);

    logAction(`Obrisana slika: ${filename}`, req.user.username);
    return res.redirect('/galerija');
  } catch (err) {
    console.log('DELETE IMAGE ERROR:', err.message);
    console.log('DELETE IMAGE TARGET:', filenameRaw);
    return res.redirect('/galerija');
  }
}

app.post('/delete/:image', async (req, res) => {
  return handleDeleteImage(req, res, req.params.image);
});

app.post('/delete', async (req, res) => {
  return handleDeleteImage(req, res, req.body.image);
});

/* ===== AUTH ===== */

app.get('/auth/discord', passport.authenticate('discord'));

app.get(
  '/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/' }),
  async (req, res) => {
    try {
      const roles = await getMemberRoles(req.user.id);
      req.user.roles = roles;
    } catch (err) {
      console.log('ROLE FETCH ERROR:', err.message);
      req.user.roles = [];
    }

    res.redirect('/');
  }
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

/* ===== START ===== */

const PORT = Number(process.env.PORT) || 3000;
initMySql().finally(() => {
  app.listen(PORT, () => console.log('FS25 Web pokrenut na portu ' + PORT));
});

