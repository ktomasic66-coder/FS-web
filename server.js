require('dotenv').config();

let mainGuild = null;

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const { Client, GatewayIntentBits } = require('discord.js');

const app = express();

/* ================= PATHS / FILES ================= */

const DATA_FILE = path.join(__dirname, 'gallery.json');
const NEWS_FILE = path.join(__dirname, 'news.json');
const RULES_FILE = path.join(__dirname, 'rules.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
const LOG_FILE = path.join(__dirname, 'admin-logs.json');

const uploadPath = path.join(__dirname, 'public/uploads');
const backupDir = path.join(__dirname, 'backups');

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
  console.log(`ðŸ¤– Bot prijavljen kao ${discordClient.user.tag}`);

  try {
    mainGuild = await discordClient.guilds.fetch(GUILD_ID);
    await mainGuild.members.fetch(); // cache members
    discordMemberCount = mainGuild.memberCount;

    console.log('ðŸ“Š Discord Älanovi:', discordMemberCount);
  } catch (err) {
    console.log('âŒ Guild error:', err.message);
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

/* ----- Gallery ----- */

function loadGallery() {
  const data = readJsonSafe(DATA_FILE, []);
  // filtriraj samo slike koje stvarno postoje
  return data.filter((img) => {
    const imagePath = path.join(__dirname, 'public/uploads', img.filename);
    return fs.existsSync(imagePath);
  });
}

function saveGallery(data) {
  writeJsonSafe(DATA_FILE, data);
}

/* ----- News ----- */

function loadNews() {
  return readJsonSafe(NEWS_FILE, []);
}

function saveNews(data) {
  writeJsonSafe(NEWS_FILE, data);
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

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* ================= ROUTES ================= */

app.get('/', (req, res) => {
  const news = loadNews();
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

app.get('/admin', requireAdmin, (req, res) => {

  const logs = loadLogs();
  const news = loadNews();        // â¬…ï¸ OVO TI FALI
  const images = loadGallery();

  res.render('admin', {
    user: req.user,
    logs: logs,
    news: news,                   // â¬…ï¸ OVO MORA BITI POSLANO
    discordMembers: discordMemberCount,
    imagesCount: images.length,
    newsCount: news.length
  });

});

/* ===== ADMIN: NEWS ===== */

app.post('/admin/news', requireAdmin, (req, res) => {
  const title = (req.body.title || '').trim();
  const content = (req.body.content || '').trim();

  if (!title || !content) return res.redirect('/admin');

  const news = loadNews();
  news.unshift({
    id: Date.now(),
    title,
    content,
    date: new Date().toLocaleString(),
    author: req.user.username,
  });
  saveNews(news);

  logAction(`News objava dodana: "${title}"`, req.user.username);
  res.redirect('/admin');
});

app.post('/admin/news/delete/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  let news = loadNews();
  const before = news.length;
  news = news.filter((n) => n.id !== id);
  saveNews(news);

  if (news.length !== before) logAction(`News obrisan (id=${id})`, req.user.username);
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

  logAction('Pravila ureÄ‘ena', req.user.username);
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
  const stats = {
    serverStatus: 'Online (ruÄno / G-Portal)',
    playersOnline: 'â€”',
    maxPlayers: 'â€”',
    discordMembers: discordMemberCount,
  };

  res.render('statistika', { user: req.user, stats });
});

/* ===== GALERIJA ===== */

app.get('/galerija', async (req, res) => {
  let roles = [];
  let isPlayer = false;
  let isAdmin = false;

  if (req.user) {
    roles = req.user.roles?.length ? req.user.roles : await getMemberRoles(req.user.id);
    isPlayer = roles.some((r) => r.id === PLAYER_ROLE_ID);
    isAdmin =
      roles.some((r) => r.id === ADMIN_ROLE_ID) ||
      hasAnyRole(req.user, [ROLE_IDS.OWNER, ROLE_IDS.CO_OWNER, ROLE_IDS.ADMIN]);
  }

  const gallery = loadGallery();

  res.render('galerija', {
    user: req.user,
    gallery,
    isPlayer,
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
  const isPlayer = roles.some((r) => r.id === PLAYER_ROLE_ID);

  if (!isPlayer) return res.redirect('/no-permission');

  upload.single('image')(req, res, function (err) {
    if (err) return res.send('GreÅ¡ka.');

    const gallery = loadGallery();

    gallery.push({
      filename: req.file.filename,
      uploaderId: req.user.id,
      uploaderName: req.user.username,
      uploaderAvatar: req.user.avatar,
      comments: [],
    });

    saveGallery(gallery);
    res.redirect('/galerija');
  });
});

/* ===== KOMENTAR (basic anti-spam) ===== */

function sanitizeComment(text) {
  const t = String(text || '').slice(0, 300); // max 300 znakova
  // osnovno â€œÄiÅ¡Ä‡enjeâ€ (nije savrÅ¡eno, ali je ok za start)
  return t.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

app.post('/comment/:image', (req, res) => {
  if (!req.user) return res.redirect('/');

  if (isBlacklisted(req.user.id)) {
    return res.send('Blokiran si za komentare.');
  }

  const gallery = loadGallery();
  const image = gallery.find((img) => img.filename === req.params.image);
  if (!image) return res.redirect('/galerija');

  const text = sanitizeComment(req.body.comment);

  if (!text.trim()) return res.redirect('/galerija');

  image.comments.push({
    user: req.user.username,
    text,
    date: new Date().toLocaleString(),
  });

  saveGallery(gallery);
  res.redirect('/galerija');
});

/* ===== DELETE (ADMIN+) ===== */

app.post('/delete/:image', async (req, res) => {
  if (!req.user) return res.redirect('/');

  const roles = req.user.roles?.length ? req.user.roles : await getMemberRoles(req.user.id);
  const isAdmin =
    roles.some((r) => r.id === ADMIN_ROLE_ID) ||
    hasAnyRole(req.user, [ROLE_IDS.OWNER, ROLE_IDS.CO_OWNER, ROLE_IDS.ADMIN]);

  if (!isAdmin) return res.redirect('/no-permission');

  const filename = req.params.image;
  const imagePath = path.join(__dirname, 'public/uploads', filename);

  // backup prije brisanja
  backupGallery();

  if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);

  let gallery = loadGallery();
  gallery = gallery.filter((img) => img.filename !== filename);
  saveGallery(gallery);

  logAction(`Obrisana slika: ${filename}`, req.user.username);
  res.redirect('/galerija');
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
app.listen(PORT, () => console.log('FS25 Web pokrenut na portu ' + PORT));

