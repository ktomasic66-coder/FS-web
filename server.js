require('dotenv').config();

let mainGuild = null;

const express = require('express');
const mongoose = require('mongoose');

// ===== MONGODB CONNECTION (Mongoose - for legacy Farm model, optional) =====
const MONGO_URI = process.env.MONGO_URI || 'mongodb://mongo:OOvotyonHPYWjWuBLnbiBSUskMFrATIU@mongodb.railway.internal:27017';
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 })
  .then(() => console.log('MongoDB connected (Slavonska Ravnica)'))
  .catch(err => console.log('MongoDB (Mongoose) not available - OK, using MongoClient for bot data'));

// ===== BOT DATABASE CONNECTION =====
// Farmbuddy bot stores data via MONGO_URL (separate from mongoose MONGO_URI).
// We use a direct MongoClient to connect to the exact same database the bot uses.
const { MongoClient } = require('mongodb');
let _botDb = null;
let _botClient = null;

async function getBotDb() {
  if (_botDb) return _botDb;

  // Use MONGO_URL (same as farmbuddy bot) — fall back to MONGO_URI if not set
  const botMongoUrl = process.env.MONGO_URL || process.env.MONGO_URI || MONGO_URI;
  if (!botMongoUrl) {
    console.error('[BOT-DB] No MONGO_URL or MONGO_URI environment variable set');
    return null;
  }

  try {
    console.log('[BOT-DB] Connecting to bot database...');
    _botClient = new MongoClient(botMongoUrl, { serverSelectionTimeoutMS: 10000 });
    await _botClient.connect();
    _botDb = _botClient.db();
    console.log('[BOT-DB] Connected to bot database:', _botDb.databaseName);

    // Verify player_links collection exists
    const cols = await _botDb.listCollections({ name: 'player_links' }).toArray();
    if (cols.length > 0) {
      console.log('[BOT-DB] player_links collection confirmed');
    } else {
      console.log('[BOT-DB] WARNING: player_links collection not found in database:', _botDb.databaseName);
      // List all collections for debugging
      const allCols = await _botDb.listCollections().toArray();
      console.log('[BOT-DB] Available collections:', allCols.map(c => c.name));
    }

    return _botDb;
  } catch (err) {
    console.error('[BOT-DB] Error connecting to bot database:', err.message);
    _botClient = null;
    _botDb = null;
    return null;
  }
}

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
const fetch = global.fetch || require('node-fetch');
const { getPlayerStats } = require('./player');
let mysql = null;
try {
  mysql = require('mysql2/promise');
} catch {
  mysql = null;
}

const { AttachmentBuilder, Client, EmbedBuilder, GatewayIntentBits } = require('discord.js');

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

/* ================= ENV ================= */

const GUILD_ID = process.env.GUILD_ID;
const PLAYER_ROLE_ID = process.env.PLAYER_ROLE_ID; // npr Player role
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;   // npr Admin role
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const GALLERY_CHANNEL_ID = process.env.GALLERY_CHANNEL_ID || '';
const IGNORED_GALLERY_BOT_IDS = new Set(['1437239146438594672']);
const WEB_LOGIN_LOG_CHANNEL_ID = '1271570784866799718';
const ADMIN_LOG_CHANNEL_ID = '1483917067777212437';

/* ===== GLOBAL ROLE IDS (za admin panel + badge) ===== */

const ROLE_IDS = {
  OWNER: '1238860450528235550',
  CO_OWNER: '1449551727010254858',
  ADMIN: '863814372610146314',
  PLAYER: '1238209853009297560',
  MEMBER: '1238854428136571000',
};

const DEFAULT_BOT_CONFIG = {
  welcome: {
    channelId: '',
    message: 'Dobrodošao {user} na server!',
  },
  logging: {
    channelId: ADMIN_LOG_CHANNEL_ID,
  },
  embeds: [],
  gallery: {
    channelId: GALLERY_CHANNEL_ID,
  },
  ticketSystem: {
    logChannelId: '',
    categoryId: '',
    supportRoleId: '',
    autoCloseHours: 48,
    reminderHours: 3,
    types: {
      igranje: {
        title: 'Igranje na serveru',
        questions: [
          'Koliko često planiraš da igraš na serveru?',
          'U koje vrijeme si najčešće aktivan?',
          'Da li si spreman da poštuješ raspored i obaveze na farmi?',
          'Kako bi reagovao ako neko iz tima ne poštuje dogovor ili pravila igre?',
          'Da li koristiš voice chat (Discord) tokom igre?',
          'Da li si spreman da pomogneš drugim igračima?',
          'Zašto želiš da igraš baš na hard serveru?',
        ],
      },
      zalba: {
        title: 'Žalba na igrače',
        questions: [
          'Ime igrača na kojeg se žališ?',
          'Vrijeme i detaljan opis situacije?',
          'Imaš li dokaze (slike, video, log)?',
        ],
      },
      modovi: {
        title: 'Edit modova',
        questions: [
          'Na čemu trenutno radiš?',
          'Koji je konkretan problem?',
          'Koji editor / verziju igre koristiš?',
        ],
      },
    },
    messages: {
      reminder:
        'Hej {user}!\nJoš uvijek nisi odgovorio na pitanja iz prve poruke u tiketu.\n\nMolimo te da odgovoriš na sva pitanja kako bismo mogli nastaviti s procesom.',
      autoClose:
        'Ticket je automatski zatvoren jer 48 sati nije bilo aktivnosti. Ako i dalje trebaš pomoć, slobodno otvori novi ticket.',
    },
  },
};

/* ================= DISCORD BOT ================= */

const discordClient = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
  ],
});

let discordMemberCount = 0;
let gallerySyncInterval = null;
let gallerySyncInProgress = false;

async function runScheduledGallerySync() {
  if (gallerySyncInProgress || !discordClient.isReady()) return 0;
  gallerySyncInProgress = true;

  try {
    return await syncGalleryFromDiscordChannel();
  } catch (err) {
    console.log('SCHEDULED GALLERY SYNC ERROR:', err.message);
    return 0;
  } finally {
    gallerySyncInProgress = false;
  }
}

discordClient.once('clientReady', async () => {
  console.log(`🤖 Bot prijavljen kao ${discordClient.user.tag}`);

  try {
    mainGuild = await discordClient.guilds.fetch(GUILD_ID);
    discordMemberCount = mainGuild.memberCount;

    console.log('📊 Discord članovi:', discordMemberCount);
    await syncGalleryFromDiscordChannel();
    await syncDiscordStateToDatabase({ includeMembers: false });
    if (!gallerySyncInterval) {
      gallerySyncInterval = setInterval(() => {
        runScheduledGallerySync().catch(() => 0);
      }, 15000);
    }
  } catch (err) {
    console.log('❌ Guild error:', err.message);
  }
});

discordClient.on('guildMemberAdd', (member) => {
  if (member.guild.id !== GUILD_ID) return;
  discordMemberCount = member.guild.memberCount;
  Promise.all([
    upsertDiscordMember(member),
    syncDiscordStateToDatabase({ includeMembers: false }),
  ]).catch((err) => {
    console.log('DISCORD MEMBER ADD SYNC ERROR:', err.message);
  });
});

discordClient.on('guildMemberRemove', (member) => {
  if (member.guild.id !== GUILD_ID) return;
  discordMemberCount = member.guild.memberCount;
  removeDiscordMember(member.id).catch((err) => {
    console.log('DISCORD MEMBER REMOVE SYNC ERROR:', err.message);
  });
});

discordClient.on('guildMemberUpdate', (_, member) => {
  if (member.guild.id !== GUILD_ID) return;
  upsertDiscordMember(member).catch((err) => {
    console.log('DISCORD MEMBER UPDATE SYNC ERROR:', err.message);
  });
});

discordClient.on('roleCreate', (role) => {
  if (role.guild.id !== GUILD_ID) return;
  upsertDiscordRole(role).catch((err) => {
    console.log('DISCORD ROLE CREATE SYNC ERROR:', err.message);
  });
});

discordClient.on('roleDelete', (role) => {
  if (role.guild.id !== GUILD_ID) return;
  removeDiscordRole(role.id).catch((err) => {
    console.log('DISCORD ROLE DELETE SYNC ERROR:', err.message);
  });
});

discordClient.on('roleUpdate', (_, role) => {
  if (role.guild.id !== GUILD_ID) return;
  upsertDiscordRole(role).catch((err) => {
    console.log('DISCORD ROLE UPDATE SYNC ERROR:', err.message);
  });
});

discordClient.on('messageCreate', (message) => {
  if (message.author?.bot) return;
  if (!message.guild || message.guild.id !== GUILD_ID) return;

  loadBotConfig()
    .then((config) => {
      const galleryChannelId = String(config.gallery?.channelId || GALLERY_CHANNEL_ID || '').trim();
      if (!galleryChannelId || message.channelId !== galleryChannelId) return null;
      return ingestDiscordGalleryMessage(message);
    })
    .catch((err) => {
      console.log('DISCORD MESSAGE SYNC ERROR:', err.message);
    });
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

function cloneDefaultBotConfig() {
  return JSON.parse(JSON.stringify(DEFAULT_BOT_CONFIG));
}

function getDiscordSnowflakeTimestamp(id) {
  try {
    if (!id) return 0;
    return Number((BigInt(String(id)) >> 22n) + 1420070400000n);
  } catch {
    return 0;
  }
}

function getGalleryItemTimestamp(item) {
  const explicit = Number(item?.uploadedAtMs || 0);
  if (explicit > 0) return explicit;

  const filenameMatch = String(item?.filename || '').match(/^(\d{10,})-/);
  if (filenameMatch) {
    const filenameTs = Number(filenameMatch[1]);
    if (Number.isFinite(filenameTs) && filenameTs > 0) return filenameTs;
  }

  const discordTs = getDiscordSnowflakeTimestamp(item?.discordMessageId);
  if (discordTs > 0) return discordTs;

  return 0;
}

function normalizeBotConfig(raw) {
  const base = cloneDefaultBotConfig();
  const cfg = raw && typeof raw === 'object' ? raw : {};

  return {
    welcome: {
      ...base.welcome,
      ...(cfg.welcome || {}),
    },
    logging: {
      ...base.logging,
      ...(cfg.logging || {}),
    },
    embeds: Array.isArray(cfg.embeds) ? cfg.embeds : base.embeds,
    gallery: {
      ...base.gallery,
      ...(cfg.gallery || {}),
    },
    ticketSystem: {
      ...base.ticketSystem,
      ...(cfg.ticketSystem || {}),
      types: {
        igranje: {
          ...base.ticketSystem.types.igranje,
          ...(cfg.ticketSystem?.types?.igranje || {}),
          questions: Array.isArray(cfg.ticketSystem?.types?.igranje?.questions)
            ? cfg.ticketSystem.types.igranje.questions.map((q) => String(q || '')).filter(Boolean)
            : [...base.ticketSystem.types.igranje.questions],
        },
        zalba: {
          ...base.ticketSystem.types.zalba,
          ...(cfg.ticketSystem?.types?.zalba || {}),
          questions: Array.isArray(cfg.ticketSystem?.types?.zalba?.questions)
            ? cfg.ticketSystem.types.zalba.questions.map((q) => String(q || '')).filter(Boolean)
            : [...base.ticketSystem.types.zalba.questions],
        },
        modovi: {
          ...base.ticketSystem.types.modovi,
          ...(cfg.ticketSystem?.types?.modovi || {}),
          questions: Array.isArray(cfg.ticketSystem?.types?.modovi?.questions)
            ? cfg.ticketSystem.types.modovi.questions.map((q) => String(q || '')).filter(Boolean)
            : [...base.ticketSystem.types.modovi.questions],
        },
      },
      messages: {
        ...base.ticketSystem.messages,
        ...(cfg.ticketSystem?.messages || {}),
      },
    },
  };
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
async function ensureColumn(tableName, columnName, definition) {
  if (!dbPool) return;

  const [rows] = await dbPool.query(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [tableName, columnName]
  );

  if (rows.length === 0) {
    await dbPool.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
}

async function initMySql() {
  if (!mysql) {
    console.log('MySQL driver nije dostupan, fallback na JSON.');
    return;
  }

  const mysqlUrl =
    process.env.MYSQL_URL ||
    process.env.MYSQL_PRIVATE_URL ||
    process.env.MYSQL_PUBLIC_URL ||
    '';
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
      console.log('MySQL init: koristim URL konekciju.');
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
      console.log(`MySQL init: koristim host konekciju (${mysqlHost}:${mysqlPort}/${mysqlDatabase}).`);
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
        uploader_avatar VARCHAR(255) DEFAULT NULL,
        description TEXT DEFAULT NULL,
        like_count INT NOT NULL DEFAULT 0,
        heart_count INT NOT NULL DEFAULT 0,
        sr_count INT NOT NULL DEFAULT 0,
        mime_type VARCHAR(120) DEFAULT NULL,
        image_data LONGBLOB DEFAULT NULL
      )
    `);

    await ensureColumn('gallery_images', 'description', 'TEXT DEFAULT NULL');
    await ensureColumn('gallery_images', 'like_count', 'INT NOT NULL DEFAULT 0');
    await ensureColumn('gallery_images', 'heart_count', 'INT NOT NULL DEFAULT 0');
    await ensureColumn('gallery_images', 'sr_count', 'INT NOT NULL DEFAULT 0');
    await ensureColumn('gallery_images', 'mime_type', 'VARCHAR(120) DEFAULT NULL');
    await ensureColumn('gallery_images', 'image_data', 'LONGBLOB DEFAULT NULL');

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

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS rules_meta (
        meta_key VARCHAR(80) PRIMARY KEY,
        meta_value TEXT NOT NULL
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS rules_items (
        id BIGINT PRIMARY KEY,
        sort_order INT NOT NULL,
        title VARCHAR(255) DEFAULT NULL,
        content TEXT DEFAULT NULL,
        text TEXT DEFAULT NULL
      )
    `);

    await ensureColumn('rules_items', 'title', 'VARCHAR(255) DEFAULT NULL');
    await ensureColumn('rules_items', 'content', 'TEXT DEFAULT NULL');

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS blacklist_entries (
        user_id VARCHAR(64) PRIMARY KEY
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS admin_logs (
        id BIGINT PRIMARY KEY,
        action VARCHAR(255) NOT NULL,
        admin VARCHAR(120) NOT NULL,
        date_text VARCHAR(120) NOT NULL
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS bot_config (
        config_key VARCHAR(80) PRIMARY KEY,
        config_value LONGTEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS discord_roles (
        role_id VARCHAR(64) PRIMARY KEY,
        guild_id VARCHAR(64) NOT NULL,
        name VARCHAR(120) NOT NULL,
        color VARCHAR(16) NOT NULL DEFAULT '#444444',
        position INT NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS discord_members (
        user_id VARCHAR(64) PRIMARY KEY,
        guild_id VARCHAR(64) NOT NULL,
        username VARCHAR(120) NOT NULL,
        global_name VARCHAR(120) DEFAULT NULL,
        avatar VARCHAR(255) DEFAULT NULL,
        joined_at VARCHAR(120) DEFAULT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS discord_member_roles (
        user_id VARCHAR(64) NOT NULL,
        role_id VARCHAR(64) NOT NULL,
        guild_id VARCHAR(64) NOT NULL,
        assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, role_id)
      )
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS gallery_reactions (
        image_filename VARCHAR(255) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        reaction_type VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (image_filename, user_id, reaction_type),
        CONSTRAINT fk_gallery_reaction_image
          FOREIGN KEY (image_filename) REFERENCES gallery_images(filename)
          ON DELETE CASCADE
      )
    `);

    await ensureColumn('gallery_images', 'source_type', "VARCHAR(20) NOT NULL DEFAULT 'web'");
    await ensureColumn('gallery_images', 'discord_message_id', 'VARCHAR(64) DEFAULT NULL');
    await ensureColumn('gallery_images', 'discord_channel_id', 'VARCHAR(64) DEFAULT NULL');
    await ensureColumn('gallery_images', 'external_url', 'TEXT DEFAULT NULL');

    useMySql = true;
    await migrateDataToMySqlIfNeeded();
    console.log('MySQL storage aktivan (news + gallery + rules + blacklist + logs).');
  } catch (err) {
    console.log('MySQL init error, fallback na JSON:', err.message);
    useMySql = false;
    dbPool = null;
  }
}

async function migrateDataToMySqlIfNeeded() {
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
      const localImagePath = path.join(uploadPath, String(image.filename || ''));
      const imageBuffer = fs.existsSync(localImagePath) ? fs.readFileSync(localImagePath) : null;
      const ext = path.extname(localImagePath).toLowerCase();
      const mimeType =
        ext === '.png' ? 'image/png' :
        ext === '.webp' ? 'image/webp' :
        ext === '.gif' ? 'image/gif' :
        imageBuffer ? 'image/jpeg' : null;

      await dbPool.query(
        `INSERT INTO gallery_images
         (filename, uploader_id, uploader_name, uploader_avatar, description, like_count, heart_count, sr_count, mime_type, image_data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          String(image.filename || ''),
          String(image.uploaderId || ''),
          String(image.uploaderName || ''),
          image.uploaderAvatar ? String(image.uploaderAvatar) : null,
          String(image.description || ''),
          Number(image.reactions?.like || 0),
          Number(image.reactions?.heart || 0),
          Number(image.reactions?.sr || 0),
          mimeType,
          imageBuffer,
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

  const [missingBlobRows] = await dbPool.query(
    'SELECT filename FROM gallery_images WHERE image_data IS NULL OR mime_type IS NULL'
  );
  for (const row of missingBlobRows) {
    const localImagePath = path.join(uploadPath, String(row.filename || ''));
    if (!fs.existsSync(localImagePath)) continue;

    const fileBuffer = fs.readFileSync(localImagePath);
    const ext = path.extname(localImagePath).toLowerCase();
    const mimeType =
      ext === '.png' ? 'image/png' :
      ext === '.webp' ? 'image/webp' :
      ext === '.gif' ? 'image/gif' :
      'image/jpeg';

    await dbPool.query(
      'UPDATE gallery_images SET image_data = ?, mime_type = COALESCE(mime_type, ?) WHERE filename = ?',
      [fileBuffer, mimeType, row.filename]
    );
  }

  const rulesFromFile = readJsonSafe(RULES_FILE, null);
  const [rulesItemsCountRows] = await dbPool.query('SELECT COUNT(*) AS c FROM rules_items');
  if (rulesItemsCountRows[0].c === 0 && rulesFromFile) {
    const normalizedRules = normalizeRulesData(rulesFromFile);
    for (let i = 0; i < normalizedRules.items.length; i += 1) {
      const item = normalizedRules.items[i];
      await dbPool.query(
        'INSERT INTO rules_items (id, sort_order, title, content, text) VALUES (?, ?, ?, ?, ?)',
        [
          Number(item.id) || Date.now() + i,
          i,
          String(item.title || ''),
          String(item.content || ''),
          String(item.text || [item.title, item.content].filter(Boolean).join('\n')),
        ]
      );
    }
  }

  const [rulesMetaCountRows] = await dbPool.query('SELECT COUNT(*) AS c FROM rules_meta');
  if (rulesMetaCountRows[0].c === 0) {
    const normalizedRules = normalizeRulesData(rulesFromFile);
    const metaEntries = [
      ['title', normalizedRules.title],
      ['subtitle', normalizedRules.subtitle],
      ['warning', normalizedRules.warning],
    ];
    for (const [metaKey, metaValue] of metaEntries) {
      await dbPool.query(
        'INSERT INTO rules_meta (meta_key, meta_value) VALUES (?, ?)',
        [metaKey, metaValue]
      );
    }
  }

  const [blacklistCountRows] = await dbPool.query('SELECT COUNT(*) AS c FROM blacklist_entries');
  if (blacklistCountRows[0].c === 0) {
    const blacklistFromFile = readJsonSafe(BLACKLIST_FILE, []);
    for (const userId of blacklistFromFile) {
      await dbPool.query(
        'INSERT IGNORE INTO blacklist_entries (user_id) VALUES (?)',
        [String(userId || '')]
      );
    }
  }

  const [logsCountRows] = await dbPool.query('SELECT COUNT(*) AS c FROM admin_logs');
  if (logsCountRows[0].c === 0) {
    const logsFromFile = readJsonSafe(LOG_FILE, []);
    for (const log of logsFromFile) {
      await dbPool.query(
        'INSERT INTO admin_logs (id, action, admin, date_text) VALUES (?, ?, ?, ?)',
        [
          Number(log.id) || Date.now(),
          String(log.action || ''),
          String(log.admin || 'system'),
          String(log.date || ''),
        ]
      );
    }
  }
}

async function loadGallery(viewerUserId = '') {
  if (!useMySql || !dbPool) {
    const data = readJsonSafe(DATA_FILE, []);
    return data
      .map((img) => ({
        ...img,
        description: String(img.description || ''),
        comments: Array.isArray(img.comments) ? img.comments : [],
        reactions: {
          like: Number(img.reactions?.like || 0),
          heart: Number(img.reactions?.heart || 0),
          sr: Number(img.reactions?.sr || 0),
        },
        viewerReactions: {
          like: Array.isArray(img.reactionUsers?.like) ? img.reactionUsers.like.includes(String(viewerUserId || '')) : false,
          heart: Array.isArray(img.reactionUsers?.heart) ? img.reactionUsers.heart.includes(String(viewerUserId || '')) : false,
          sr: Array.isArray(img.reactionUsers?.sr) ? img.reactionUsers.sr.includes(String(viewerUserId || '')) : false,
        },
        uploadedAtMs: getGalleryItemTimestamp(img),
      }))
      .filter((img) => {
        const imagePath = path.join(__dirname, 'public/uploads', img.filename);
        return fs.existsSync(imagePath);
      })
      .sort((a, b) => Number(b.uploadedAtMs || 0) - Number(a.uploadedAtMs || 0));
  }

  const [imageRows] = await dbPool.query(
    `SELECT filename, uploader_id, uploader_name, uploader_avatar, description,
            like_count, heart_count, sr_count, mime_type, source_type,
            discord_message_id, discord_channel_id, external_url
     FROM gallery_images`
  );
  const [commentRows] = await dbPool.query(
    'SELECT image_filename, user_name, text, date_text FROM gallery_comments ORDER BY id ASC'
  );
  const [reactionRows] = viewerUserId
    ? await dbPool.query(
        `SELECT image_filename, reaction_type
         FROM gallery_reactions
         WHERE user_id = ?`,
        [String(viewerUserId)]
      )
    : [[]];

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

  const viewerReactionMap = new Map();
  for (const row of reactionRows) {
    const current = viewerReactionMap.get(row.image_filename) || {};
    current[String(row.reaction_type || '')] = true;
    viewerReactionMap.set(row.image_filename, current);
  }

  return imageRows
    .map((row) => ({
      filename: row.filename,
      uploaderId: row.uploader_id,
      uploaderName: row.uploader_name,
      uploaderAvatar: row.uploader_avatar,
      description: row.description || '',
      mimeType: row.mime_type || '',
      sourceType: row.source_type || 'web',
      discordMessageId: row.discord_message_id || '',
      discordChannelId: row.discord_channel_id || '',
      externalUrl: row.external_url || '',
      comments: commentsByImage.get(row.filename) || [],
      reactions: {
        like: Number(row.like_count || 0),
        heart: Number(row.heart_count || 0),
        sr: Number(row.sr_count || 0),
      },
      viewerReactions: {
        like: Boolean(viewerReactionMap.get(row.filename)?.like),
        heart: Boolean(viewerReactionMap.get(row.filename)?.heart),
        sr: Boolean(viewerReactionMap.get(row.filename)?.sr),
      },
      uploadedAtMs: getGalleryItemTimestamp({
        filename: row.filename,
        discordMessageId: row.discord_message_id,
      }),
    }))
    .sort((a, b) => Number(b.uploadedAtMs || 0) - Number(a.uploadedAtMs || 0));
}

async function addGalleryImage(item) {
  if (!useMySql || !dbPool) {
    const gallery = readJsonSafe(DATA_FILE, []);
    gallery.push({
      ...item,
      description: String(item.description || ''),
      comments: Array.isArray(item.comments) ? item.comments : [],
      mimeType: String(item.mimeType || ''),
      sourceType: String(item.sourceType || 'web'),
      discordMessageId: String(item.discordMessageId || ''),
      discordChannelId: String(item.discordChannelId || ''),
      externalUrl: String(item.externalUrl || ''),
      reactionUsers: item.reactionUsers || { like: [], heart: [], sr: [] },
      reactions: {
        like: Number(item.reactions?.like || 0),
        heart: Number(item.reactions?.heart || 0),
        sr: Number(item.reactions?.sr || 0),
      },
    });
    writeJsonSafe(DATA_FILE, gallery);
    return;
  }

  await dbPool.query(
    `INSERT INTO gallery_images
      (filename, uploader_id, uploader_name, uploader_avatar, description, like_count, heart_count, sr_count, mime_type, image_data, source_type, discord_message_id, discord_channel_id, external_url)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       uploader_id = VALUES(uploader_id),
       uploader_name = VALUES(uploader_name),
       uploader_avatar = VALUES(uploader_avatar),
       description = VALUES(description),
       like_count = VALUES(like_count),
       heart_count = VALUES(heart_count),
       sr_count = VALUES(sr_count),
       mime_type = COALESCE(VALUES(mime_type), mime_type),
       image_data = COALESCE(VALUES(image_data), image_data),
       source_type = VALUES(source_type),
       discord_message_id = COALESCE(VALUES(discord_message_id), discord_message_id),
       discord_channel_id = COALESCE(VALUES(discord_channel_id), discord_channel_id),
       external_url = COALESCE(VALUES(external_url), external_url)`,
    [
      item.filename,
      item.uploaderId,
      item.uploaderName,
      item.uploaderAvatar || null,
      item.description || '',
      Number(item.reactions?.like || 0),
      Number(item.reactions?.heart || 0),
      Number(item.reactions?.sr || 0),
      item.mimeType || null,
      item.imageData || null,
      item.sourceType || 'web',
      item.discordMessageId || null,
      item.discordChannelId || null,
      item.externalUrl || null,
    ]
  );
}

async function getGalleryImageBinary(filename) {
  if (!useMySql || !dbPool) return null;

  const [rows] = await dbPool.query(
    'SELECT mime_type, image_data, external_url FROM gallery_images WHERE filename = ? LIMIT 1',
    [filename]
  );

  if (!rows.length) return null;

  if (rows[0].image_data) {
    return {
      type: 'binary',
      mimeType: rows[0].mime_type || 'image/jpeg',
      buffer: rows[0].image_data,
    };
  }

  if (rows[0].external_url) {
    return {
      type: 'redirect',
      url: rows[0].external_url,
    };
  }

  return null;
}

async function updateGalleryImageDiscordMessage(filename, payload) {
  if (!useMySql || !dbPool || !filename) return;

  await dbPool.query(
    `UPDATE gallery_images
     SET discord_message_id = COALESCE(?, discord_message_id),
         discord_channel_id = COALESCE(?, discord_channel_id),
         external_url = COALESCE(?, external_url)
     WHERE filename = ?`,
    [
      payload?.discordMessageId || null,
      payload?.discordChannelId || null,
      payload?.externalUrl || null,
      filename,
    ]
  );
}

async function toggleGalleryReaction(filename, userId, reactionType) {
  const allowed = {
    like: 'like',
    heart: 'heart',
    sr: 'sr',
  };

  const reaction = allowed[reactionType];
  if (!reaction || !userId) return false;

  if (!useMySql || !dbPool) {
    const gallery = readJsonSafe(DATA_FILE, []);
    const image = gallery.find((img) => img.filename === filename);
    if (!image) return false;
    image.reactions = image.reactions || {};
    image.reactionUsers = image.reactionUsers || { like: [], heart: [], sr: [] };
    image.reactionUsers[reaction] = Array.isArray(image.reactionUsers[reaction])
      ? image.reactionUsers[reaction]
      : [];

    const existing = image.reactionUsers[reaction].includes(String(userId));
    if (existing) {
      image.reactionUsers[reaction] = image.reactionUsers[reaction].filter((id) => id !== String(userId));
      image.reactions[reaction] = Math.max(0, Number(image.reactions[reaction] || 0) - 1);
    } else {
      image.reactionUsers[reaction].push(String(userId));
      image.reactions[reaction] = Number(image.reactions[reaction] || 0) + 1;
    }
    writeJsonSafe(DATA_FILE, gallery);
    return true;
  }

  const [rows] = await dbPool.query(
    `SELECT reaction_type
     FROM gallery_reactions
     WHERE image_filename = ? AND user_id = ? AND reaction_type = ?
     LIMIT 1`,
    [filename, String(userId), reaction]
  );

  if (rows.length) {
    await dbPool.query(
      `DELETE FROM gallery_reactions
       WHERE image_filename = ? AND user_id = ? AND reaction_type = ?`,
      [filename, String(userId), reaction]
    );
    await dbPool.query(
      `UPDATE gallery_images
       SET ${reaction}_count = GREATEST(${reaction}_count - 1, 0)
       WHERE filename = ?`,
      [filename]
    );
    return true;
  }

  await dbPool.query(
    `INSERT INTO gallery_reactions (image_filename, user_id, reaction_type)
     VALUES (?, ?, ?)`,
    [filename, String(userId), reaction]
  );
  await dbPool.query(
    `UPDATE gallery_images
     SET ${reaction}_count = ${reaction}_count + 1
     WHERE filename = ?`,
    [filename]
  );
  return true;
}

async function addGalleryComment(filename, comment) {
  if (!useMySql || !dbPool) {
    const gallery = readJsonSafe(DATA_FILE, []);
    const image = gallery.find((img) => img.filename === filename);
    if (!image) return false;
    if (!Array.isArray(image.comments)) image.comments = [];
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

function normalizeRulesData(raw) {
  const fallback = {
    title: 'Pravila Ponašanja',
    subtitle: 'Ova pravila važe za sve članove servera bez izuzetka.',
    warning: 'Kršenje pravila može rezultirati upozorenjem, mute-om ili trajnim banom.',
    items: [],
  };

  const normalizeCroatianText = (value) => {
    const text = String(value || '').trim();

    if (text === 'Pravila Ponasanja') return 'Pravila Ponašanja';
    if (text === 'Ova pravila vaze za sve clanove servera bez izuzetka.') {
      return 'Ova pravila važe za sve članove servera bez izuzetka.';
    }
    if (text === 'Krsenje pravila moze rezultirati upozorenjem, mute-om ili trajnim banom.') {
      return 'Kršenje pravila može rezultirati upozorenjem, mute-om ili trajnim banom.';
    }

    return text;
  };

  const normalizeRuleItem = (item, index) => {
    if (!item) return null;

    const legacyText = normalizeCroatianText(item.text || '');
    const explicitTitle = normalizeCroatianText(item.title || '');
    const explicitContent = normalizeCroatianText(item.content || '');

    let title = explicitTitle;
    let content = explicitContent;

    if (!title && legacyText) {
      const parts = legacyText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      if (parts.length > 1) {
        title = parts.shift();
        content = parts.join('\n');
      } else {
        const colonIndex = legacyText.indexOf(':');
        if (colonIndex > 0 && colonIndex < 80) {
          title = legacyText.slice(0, colonIndex).trim();
          content = legacyText.slice(colonIndex + 1).trim();
        } else {
          title = `Pravilo ${String(index + 1).padStart(2, '0')}`;
          content = legacyText;
        }
      }
    }

    if (!title && !content) return null;

    return {
      id: Number(item.id) || Date.now() + index,
      title: title || `Pravilo ${String(index + 1).padStart(2, '0')}`,
      content: content || '',
      text: [title, content].filter(Boolean).join('\n'),
    };
  };

  if (!raw || typeof raw !== 'object') return fallback;

  if (Array.isArray(raw.items)) {
    return {
      title: normalizeCroatianText(raw.title || fallback.title),
      subtitle: normalizeCroatianText(raw.subtitle || fallback.subtitle),
      warning: normalizeCroatianText(raw.warning || fallback.warning),
      items: raw.items
        .map((item, index) => normalizeRuleItem(item, index))
        .filter(Boolean),
    };
  }

  const legacyLines = String(raw.content || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  return {
    ...fallback,
    items: legacyLines.map((text, index) => ({
      id: Date.now() + index,
      title: `Pravilo ${String(index + 1).padStart(2, '0')}`,
      content: normalizeCroatianText(text),
      text: normalizeCroatianText(text),
    })),
  };
}

async function loadRules() {
  if (!useMySql || !dbPool) {
    return normalizeRulesData(readJsonSafe(RULES_FILE, null));
  }

  const [metaRows] = await dbPool.query(
    'SELECT meta_key, meta_value FROM rules_meta WHERE meta_key IN (?,?,?)',
    ['title', 'subtitle', 'warning']
  );
  const [itemRows] = await dbPool.query(
    'SELECT id, title, content, text FROM rules_items ORDER BY sort_order ASC, id ASC'
  );

  const meta = Object.fromEntries(metaRows.map((row) => [row.meta_key, row.meta_value]));
  return {
    title: normalizeRulesData({ title: meta.title }).title,
    subtitle: normalizeRulesData({ subtitle: meta.subtitle }).subtitle,
    warning: normalizeRulesData({ warning: meta.warning }).warning,
    items: normalizeRulesData({
      items: itemRows.map((row) => ({
        id: Number(row.id),
        title: row.title,
        content: row.content,
        text: row.text,
      })),
    }).items,
  };
}

async function saveRules(data) {
  if (!useMySql || !dbPool) {
    writeJsonSafe(RULES_FILE, data);
    return;
  }

  const rules = normalizeRulesData(data);
  await dbPool.query('DELETE FROM rules_items');
  await dbPool.query('DELETE FROM rules_meta');

  const metaEntries = [
    ['title', rules.title],
    ['subtitle', rules.subtitle],
    ['warning', rules.warning],
  ];

  for (const [metaKey, metaValue] of metaEntries) {
    await dbPool.query(
      'INSERT INTO rules_meta (meta_key, meta_value) VALUES (?, ?)',
      [metaKey, metaValue]
    );
  }

  for (let i = 0; i < rules.items.length; i += 1) {
    const item = rules.items[i];
    await dbPool.query(
      'INSERT INTO rules_items (id, sort_order, title, content, text) VALUES (?, ?, ?, ?, ?)',
      [
        Number(item.id) || Date.now() + i,
        i,
        String(item.title || ''),
        String(item.content || ''),
        String(item.text || [item.title, item.content].filter(Boolean).join('\n')),
      ]
    );
  }
}

async function loadBotConfig() {
  if (!useMySql || !dbPool) {
    return cloneDefaultBotConfig();
  }

  const [rows] = await dbPool.query(
    'SELECT config_value FROM bot_config WHERE config_key = ? LIMIT 1',
    ['ticket-bot']
  );

  if (!rows.length) {
    const defaults = cloneDefaultBotConfig();
    await saveBotConfig(defaults);
    return defaults;
  }

  try {
    return normalizeBotConfig(JSON.parse(rows[0].config_value));
  } catch {
    const defaults = cloneDefaultBotConfig();
    await saveBotConfig(defaults);
    return defaults;
  }
}

async function saveBotConfig(config) {
  if (!useMySql || !dbPool) return;

  const normalized = normalizeBotConfig(config);
  await dbPool.query(
    `INSERT INTO bot_config (config_key, config_value)
     VALUES (?, ?)
     ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)`,
    ['ticket-bot', JSON.stringify(normalized, null, 2)]
  );
}

async function loadSyncedGuildRoles() {
  if (!useMySql || !dbPool) return [];

  const [rows] = await dbPool.query(
    `SELECT role_id AS id, name, color, position
     FROM discord_roles
     WHERE guild_id = ?
     ORDER BY position DESC, name ASC`,
    [GUILD_ID]
  );

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    color: row.color || '#444',
    position: Number(row.position || 0),
  }));
}

async function loadSyncedMemberRoles(userId) {
  if (!useMySql || !dbPool || !userId) return [];

  const [rows] = await dbPool.query(
    `SELECT r.role_id AS id, r.name, r.color, r.position
     FROM discord_member_roles mr
     INNER JOIN discord_roles r ON r.role_id = mr.role_id
     WHERE mr.guild_id = ? AND mr.user_id = ?
     ORDER BY r.position DESC, r.name ASC`,
    [GUILD_ID, String(userId)]
  );

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    color: row.color || '#444',
    position: Number(row.position || 0),
  }));
}

async function loadDiscordSyncStats() {
  if (!useMySql || !dbPool) {
    return {
      rolesCount: 0,
      membersCount: 0,
      memberRolesCount: 0,
    };
  }

  const [[rolesRows], [membersRows], [memberRolesRows]] = await Promise.all([
    dbPool.query('SELECT COUNT(*) AS c FROM discord_roles WHERE guild_id = ?', [GUILD_ID]),
    dbPool.query('SELECT COUNT(*) AS c FROM discord_members WHERE guild_id = ?', [GUILD_ID]),
    dbPool.query('SELECT COUNT(*) AS c FROM discord_member_roles WHERE guild_id = ?', [GUILD_ID]),
  ]);

  return {
    rolesCount: Number(rolesRows[0]?.c || 0),
    membersCount: Number(membersRows[0]?.c || 0),
    memberRolesCount: Number(memberRolesRows[0]?.c || 0),
  };
}

async function upsertDiscordRole(role) {
  if (!useMySql || !dbPool || !mainGuild || !role || role.name === '@everyone') return;

  await dbPool.query(
    `INSERT INTO discord_roles (role_id, guild_id, name, color, position)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       guild_id = VALUES(guild_id),
       name = VALUES(name),
       color = VALUES(color),
       position = VALUES(position)`,
    [
      role.id,
      mainGuild.id,
      role.name,
      role.hexColor && role.hexColor !== '#000000' ? role.hexColor : '#444444',
      Number(role.position || 0),
    ]
  );
}

async function removeDiscordRole(roleId) {
  if (!useMySql || !dbPool || !mainGuild || !roleId) return;

  await dbPool.query('DELETE FROM discord_roles WHERE guild_id = ? AND role_id = ?', [mainGuild.id, String(roleId)]);
  await dbPool.query('DELETE FROM discord_member_roles WHERE guild_id = ? AND role_id = ?', [mainGuild.id, String(roleId)]);
}

async function upsertDiscordMember(member) {
  if (!useMySql || !dbPool || !mainGuild || !member) return;

  await dbPool.query(
    `INSERT INTO discord_members (user_id, guild_id, username, global_name, avatar, joined_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       guild_id = VALUES(guild_id),
       username = VALUES(username),
       global_name = VALUES(global_name),
       avatar = VALUES(avatar),
       joined_at = VALUES(joined_at)`,
    [
      member.id,
      mainGuild.id,
      member.user.username,
      member.user.globalName || null,
      member.user.avatar || null,
      member.joinedAt ? member.joinedAt.toISOString() : null,
    ]
  );

  await dbPool.query('DELETE FROM discord_member_roles WHERE guild_id = ? AND user_id = ?', [mainGuild.id, member.id]);

  const memberRoles = member.roles.cache
    .filter((role) => role.name !== '@everyone')
    .map((role) => role.id);

  for (const roleId of memberRoles) {
    await dbPool.query(
      `INSERT INTO discord_member_roles (user_id, role_id, guild_id)
       VALUES (?, ?, ?)`,
      [member.id, roleId, mainGuild.id]
    );
  }
}

async function removeDiscordMember(userId) {
  if (!useMySql || !dbPool || !mainGuild || !userId) return;

  await dbPool.query('DELETE FROM discord_member_roles WHERE guild_id = ? AND user_id = ?', [mainGuild.id, String(userId)]);
  await dbPool.query('DELETE FROM discord_members WHERE guild_id = ? AND user_id = ?', [mainGuild.id, String(userId)]);
}

async function syncDiscordStateToDatabase({ includeMembers = false } = {}) {
  if (!useMySql || !dbPool || !mainGuild) return;

  await mainGuild.roles.fetch();

  const roles = mainGuild.roles.cache
    .filter((role) => role.name !== '@everyone')
    .sort((a, b) => b.position - a.position);

  const roleIds = roles.map((role) => role.id);
  for (const role of roles.values()) {
    await upsertDiscordRole(role);
  }

  if (roleIds.length) {
    const placeholders = roleIds.map(() => '?').join(', ');
    await dbPool.query(
      `DELETE FROM discord_roles WHERE guild_id = ? AND role_id NOT IN (${placeholders})`,
      [mainGuild.id, ...roleIds]
    );
  } else {
    await dbPool.query('DELETE FROM discord_roles WHERE guild_id = ?', [mainGuild.id]);
  }

  if (!includeMembers) return;

  await mainGuild.members.fetch();
  const members = mainGuild.members.cache;
  const memberIds = members.map((member) => member.id);

  for (const member of members.values()) {
    await upsertDiscordMember(member);
  }

  if (memberIds.length) {
    const placeholders = memberIds.map(() => '?').join(', ');
    await dbPool.query(
      `DELETE FROM discord_members WHERE guild_id = ? AND user_id NOT IN (${placeholders})`,
      [mainGuild.id, ...memberIds]
    );
    await dbPool.query(
      `DELETE FROM discord_member_roles WHERE guild_id = ? AND user_id NOT IN (${placeholders})`,
      [mainGuild.id, ...memberIds]
    );
  } else {
    await dbPool.query('DELETE FROM discord_members WHERE guild_id = ?', [mainGuild.id]);
    await dbPool.query('DELETE FROM discord_member_roles WHERE guild_id = ?', [mainGuild.id]);
  }
}

let discordSyncTimer = null;

function scheduleDiscordStateSync() {
  if (discordSyncTimer) clearTimeout(discordSyncTimer);
  discordSyncTimer = setTimeout(() => {
    syncDiscordStateToDatabase({ includeMembers: false }).catch((err) => {
      console.log('DISCORD SYNC ERROR:', err.message);
    });
  }, 1500);
}

async function hydrateUserRoles(user) {
  if (!user || !user.id) return [];

  const dbRoles = await loadSyncedMemberRoles(user.id);
  if (dbRoles.length) {
    user.roles = dbRoles;
    return dbRoles;
  }

  const liveRoles = await getMemberRoles(user.id);
  user.roles = liveRoles;
  return liveRoles;
}

async function addRule(title, content) {
  const rules = await loadRules();
  rules.items.push({
    id: Date.now(),
    title,
    content,
    text: [title, content].filter(Boolean).join('\n'),
  });
  await saveRules(rules);
}

async function getRuleById(id) {
  const rules = await loadRules();
  return rules.items.find((item) => Number(item.id) === Number(id)) || null;
}

async function updateRuleById(id, title, content) {
  const rules = await loadRules();
  const rule = rules.items.find((item) => Number(item.id) === Number(id));
  if (!rule) return null;
  const before = {
    id: rule.id,
    title: rule.title,
    content: rule.content,
  };
  rule.title = title;
  rule.content = content;
  rule.text = [title, content].filter(Boolean).join('\n');
  await saveRules(rules);
  return {
    before,
    after: {
      id: rule.id,
      title: rule.title,
      content: rule.content,
    },
  };
}

async function deleteRuleById(id) {
  const rules = await loadRules();
  const deletedRule = rules.items.find((item) => Number(item.id) === Number(id)) || null;
  rules.items = rules.items.filter((item) => Number(item.id) !== Number(id));
  await saveRules(rules);
  return deletedRule;
}

async function updateRulesMeta({ title, subtitle, warning }) {
  const rules = await loadRules();
  rules.title = title || rules.title;
  rules.subtitle = subtitle || rules.subtitle;
  rules.warning = warning || rules.warning;
  await saveRules(rules);
}

/* ----- Logs ----- */

async function loadLogs() {
  if (!useMySql || !dbPool) {
    return readJsonSafe(LOG_FILE, []);
  }

  const [rows] = await dbPool.query(
    'SELECT id, action, admin, date_text AS date FROM admin_logs ORDER BY id DESC'
  );
  return rows;
}

function getAdminLogActionText(action) {
  if (typeof action === 'string') return action;
  if (action && typeof action.summary === 'string') return action.summary;
  return 'Admin akcija';
}

function formatRuleLogSnapshot(rule) {
  if (!rule) return 'N/A';
  const title = String(rule.title || '').trim();
  const content = String(rule.content || '').trim();
  return [`Naslov: ${title || 'N/A'}`, `Sadrzaj: ${content || 'N/A'}`].join('\n');
}

async function logAction(action, adminUser, discordPayload = null) {
  const actionText = getAdminLogActionText(action);

  if (!useMySql || !dbPool) {
    const logs = readJsonSafe(LOG_FILE, []);
    logs.unshift({
      id: Date.now(),
      action: actionText,
      admin: adminUser,
      date: new Date().toLocaleString(),
    });
    writeJsonSafe(LOG_FILE, logs);
    await sendAdminActionDiscordLog(actionText, adminUser, discordPayload);
    return;
  }

  await dbPool.query(
    'INSERT INTO admin_logs (id, action, admin, date_text) VALUES (?, ?, ?, ?)',
    [Date.now(), actionText, adminUser, new Date().toLocaleString()]
  );
  await sendAdminActionDiscordLog(actionText, adminUser, discordPayload);
}

async function sendWebLoginDiscordLog(user) {
  if (!user || !discordClient.isReady()) return;

  let channelId = WEB_LOGIN_LOG_CHANNEL_ID;
  try {
    const botConfig = await loadBotConfig();
    channelId = String(botConfig.logging?.channelId || WEB_LOGIN_LOG_CHANNEL_ID || '').trim();
  } catch {
    channelId = WEB_LOGIN_LOG_CHANNEL_ID;
  }

  if (!channelId) return;

  const channel = await discordClient.channels.fetch(channelId).catch(() => null);
  if (!channel || !channel.isTextBased()) return;

  const roleNames = Array.isArray(user.roles) ? user.roles.map((role) => role.name).filter(Boolean) : [];
  const lines = [
    'Prijava na web stranicu',
    `Korisnik: ${user.username} (${user.id})`,
    `Vrijeme: ${new Date().toLocaleString('hr-HR')}`,
    roleNames.length ? `Role: ${roleNames.join(', ')}` : '',
  ].filter(Boolean);

  await channel.send(lines.join('\n')).catch((err) => {
    console.log('WEB LOGIN LOG ERROR:', err.message);
  });
}

async function sendAdminActionDiscordLog(action, adminUser, payload = null) {
  if (!discordClient.isReady()) return;

  let channelId = ADMIN_LOG_CHANNEL_ID;
  try {
    const botConfig = await loadBotConfig();
    channelId = String(botConfig.logging?.channelId || ADMIN_LOG_CHANNEL_ID || '').trim();
  } catch {
    channelId = ADMIN_LOG_CHANNEL_ID;
  }

  if (!channelId) return;

  const channel = await discordClient.channels.fetch(channelId).catch(() => null);
  if (!channel || !channel.isTextBased()) return;

  const embed = new EmbedBuilder()
    .setTitle(payload?.title || 'Admin log')
    .setColor(0xf1c40f)
    .addFields(
      { name: 'Admin', value: String(adminUser || 'Nepoznat'), inline: true },
      { name: 'Akcija', value: String(action || 'N/A'), inline: true },
      { name: 'Vrijeme', value: new Date().toLocaleString('hr-HR'), inline: false }
    )
    .setTimestamp(new Date());

  if (payload?.before) {
    embed.addFields({
      name: 'Prije',
      value: formatRuleLogSnapshot(payload.before).slice(0, 1024),
      inline: false,
    });
  }

  if (payload?.after) {
    embed.addFields({
      name: 'Sada',
      value: formatRuleLogSnapshot(payload.after).slice(0, 1024),
      inline: false,
    });
  }

  if (payload?.details) {
    embed.addFields({
      name: 'Detalji',
      value: String(payload.details).slice(0, 1024),
      inline: false,
    });
  }

  await channel.send({ embeds: [embed] }).catch((err) => {
    console.log('ADMIN LOG DISCORD ERROR:', err.message);
  });
}

/* ----- Blacklist ----- */

async function loadBlacklist() {
  if (!useMySql || !dbPool) {
    return readJsonSafe(BLACKLIST_FILE, []);
  }

  const [rows] = await dbPool.query(
    'SELECT user_id FROM blacklist_entries ORDER BY user_id ASC'
  );
  return rows.map((row) => row.user_id);
}

async function isBlacklisted(userId) {
  if (!useMySql || !dbPool) {
    return (await loadBlacklist()).includes(userId);
  }

  const [rows] = await dbPool.query(
    'SELECT user_id FROM blacklist_entries WHERE user_id = ? LIMIT 1',
    [userId]
  );
  return rows.length > 0;
}

async function addToBlacklist(userId) {
  if (!useMySql || !dbPool) {
    const list = await loadBlacklist();
    if (!list.includes(userId)) list.push(userId);
    writeJsonSafe(BLACKLIST_FILE, list);
    return;
  }

  await dbPool.query(
    'INSERT IGNORE INTO blacklist_entries (user_id) VALUES (?)',
    [userId]
  );
}

async function removeFromBlacklist(userId) {
  if (!useMySql || !dbPool) {
    let list = await loadBlacklist();
    list = list.filter((id) => id !== userId);
    writeJsonSafe(BLACKLIST_FILE, list);
    return;
  }

  await dbPool.query(
    'DELETE FROM blacklist_entries WHERE user_id = ?',
    [userId]
  );
}

async function resolveBlacklistEntries(userIds) {
  const ids = Array.isArray(userIds) ? userIds : [];

  return Promise.all(ids.map(async (userId) => {
    let username = null;

    try {
      if (mainGuild) {
        const member = await mainGuild.members.fetch(userId);
        username = member.displayName || member.user.globalName || member.user.username;
      } else {
        const user = await discordClient.users.fetch(userId);
        username = user.globalName || user.username;
      }
    } catch {
      username = null;
    }

    return {
      userId,
      username,
    };
  }));
}

/* ----- Backup ----- */

function backupGallery() {
  if (useMySql) return;
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

  const fileName = `backup-${Date.now()}.json`;
  if (!fs.existsSync(DATA_FILE)) writeJsonSafe(DATA_FILE, []);

  fs.copyFileSync(DATA_FILE, path.join(backupDir, fileName));
}

function sanitizeGalleryFilename(name) {
  return String(name || 'image')
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 120);
}

async function publishGalleryImageToDiscord(item, buffer) {
  const botConfig = await loadBotConfig();
  const channelId = String(botConfig.gallery?.channelId || GALLERY_CHANNEL_ID || '').trim();
  if (!channelId || !buffer || !discordClient.isReady()) return null;

  const channel = await discordClient.channels.fetch(channelId).catch(() => null);
  if (!channel || !channel.isTextBased()) return null;

  const fileName = sanitizeGalleryFilename(item.filename || 'image.jpg');
  const attachment = new AttachmentBuilder(buffer, { name: fileName });
  const content = [
    'Nova slika sa web galerije',
    item.description ? `Opis: ${item.description}` : '',
    item.uploaderName ? `Autor: ${item.uploaderName}` : '',
  ]
    .filter(Boolean)
    .join('\n');

  const sent = await channel.send({
    content,
    files: [attachment],
  });

  const firstAttachment = sent.attachments.first();
  await updateGalleryImageDiscordMessage(item.filename, {
    discordMessageId: sent.id,
    discordChannelId: channel.id,
    externalUrl: firstAttachment?.url || null,
  });

  return sent;
}

function isDiscordImageAttachment(attachment) {
  if (!attachment) return false;

  const contentType = String(attachment.contentType || '').toLowerCase();
  if (contentType.startsWith('image/')) return true;
  if (Number(attachment.width || 0) > 0 || Number(attachment.height || 0) > 0) return true;

  const name = String(attachment.name || '').toLowerCase();
  return /\.(png|jpe?g|gif|webp|bmp|svg)$/i.test(name);
}

async function ingestDiscordGalleryMessage(message) {
  if (!message) return 0;
  if (IGNORED_GALLERY_BOT_IDS.has(String(message.author?.id || ''))) return 0;
  if (message.author?.bot && String(message.author?.id || '') !== String(discordClient.user?.id || '')) return 0;

  const attachments = Array.from(message.attachments.values()).filter((attachment) => {
    return isDiscordImageAttachment(attachment);
  });

  if (!attachments.length) return 0;

  const existingFilenames = new Set();
  if (useMySql && dbPool) {
    const [existingRows] = await dbPool.query(
      'SELECT filename FROM gallery_images WHERE discord_message_id = ?',
      [message.id]
    );
    existingRows.forEach((row) => existingFilenames.add(String(row.filename || '')));
  } else {
    const gallery = readJsonSafe(DATA_FILE, []);
    gallery
      .filter((image) => String(image.discordMessageId || '') === String(message.id))
      .forEach((image) => existingFilenames.add(String(image.filename || '')));
  }

  let created = 0;
  for (let index = 0; index < attachments.length; index += 1) {
    const attachment = attachments[index];
    const filename = `discord-${message.id}-${index}-${sanitizeGalleryFilename(attachment.name || 'image')}`;
    if (existingFilenames.has(filename)) continue;

    let fileBuffer = null;
    try {
      const response = await fetch(attachment.url);
      if (response.ok) {
        const arrayBuffer = await response.arrayBuffer();
        fileBuffer = Buffer.from(arrayBuffer);
      }
    } catch (err) {
      console.log('DISCORD GALLERY FETCH ERROR:', err.message);
    }

    if (!useMySql && fileBuffer) {
      const localPath = path.join(uploadPath, filename);
      fs.writeFileSync(localPath, fileBuffer);
    }

    await addGalleryImage({
      filename,
      uploaderId: message.author?.id || 'discord',
      uploaderName: message.member?.displayName || message.author?.username || 'Discord',
      uploaderAvatar: message.author?.avatar || null,
      description: String(message.content || '').replace(/WEB_FILE:[^\s]+/g, '').trim(),
      mimeType: attachment.contentType || null,
      imageData: fileBuffer,
      sourceType: 'discord',
      discordMessageId: message.id,
      discordChannelId: message.channelId,
      externalUrl: attachment.url,
      reactions: { like: 0, heart: 0, sr: 0 },
    });
    created += 1;
  }

  return created;
}

async function syncGalleryFromDiscordChannel() {
  const botConfig = await loadBotConfig();
  const channelId = String(botConfig.gallery?.channelId || GALLERY_CHANNEL_ID || '').trim();
  if (!channelId || !discordClient.isReady()) return 0;

  const channel = await discordClient.channels.fetch(channelId).catch(() => null);
  if (!channel || !channel.isTextBased()) return 0;

  const messages = await channel.messages.fetch({ limit: 100 }).catch(() => null);
  if (!messages) return 0;

  let imported = 0;
  for (const message of messages.values()) {
    imported += await ingestDiscordGalleryMessage(message);
  }

  return imported;
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

async function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/');

  const roles = await hydrateUserRoles(req.user);
  const ok = hasAnyRole({ roles }, [ROLE_IDS.OWNER, ROLE_IDS.CO_OWNER, ROLE_IDS.ADMIN]);
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

const storage = multer.memoryStorage();

const upload = multer({ storage });

/* ================= EXPRESS ================= */

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('trust proxy', 1);

app.get('/uploads/:filename', async (req, res, next) => {
  const filename = String(req.params.filename || '').trim();
  if (!filename) return res.status(404).end();

  const localPath = path.join(uploadPath, filename);
  if (fs.existsSync(localPath)) {
    return res.sendFile(localPath);
  }

  const imageFile = await getGalleryImageBinary(filename);
  if (!imageFile) return next();

  if (imageFile.type === 'redirect') {
    return res.redirect(imageFile.url);
  }

  res.setHeader('Content-Type', imageFile.mimeType);
  return res.send(imageFile.buffer);
});

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

app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.canAdminNav = false;

  if (req.user) {
    const roles = await hydrateUserRoles(req.user);
    res.locals.canAdminNav = hasAnyRole({ roles }, [ROLE_IDS.OWNER, ROLE_IDS.CO_OWNER, ROLE_IDS.ADMIN]);
  }

  next();
});

/* ================= ROUTES ================= */

app.get('/', async (req, res) => {
  const news = await loadNews();

  // Fetch active farms overview from bot database
  let farmsOverview = [];
  try {
    const db = await getBotDb();
    if (db) {
      const allFarms = await db.collection('farms').find().toArray();
      const allFields = await db.collection('fields').find().toArray();
      const allPlayers = await db.collection('players').find().toArray();

      farmsOverview = allFarms
        .filter(f => f.farmId && !String(f.farmId).startsWith('U:'))
        .map(farm => {
          const fid = String(farm.farmId);
          const farmFields = allFields.filter(f => String(f.ownerFarmId) === fid);
          const farmPlayers = allPlayers.filter(p => String(p.farmId) === fid);
          const totalArea = farmFields.reduce((sum, f) => sum + (parseFloat(f.fieldArea) || 0), 0);

          return {
            farmId: farm.farmId,
            name: farm.name || ('Farma ' + farm.farmId),
            balance: farm.balance || 0,
            fieldCount: farmFields.length,
            totalArea: totalArea,
            players: farmPlayers.map(p => ({
              name: p.name,
              isOnline: !!p.isOnline,
            })),
          };
        })
        .sort((a, b) => Number(a.farmId) - Number(b.farmId));
    }
  } catch (err) {
    console.error('[INDEX] Error fetching farms overview:', err.message);
  }

  res.render('index', { user: req.user, news, farmsOverview });
});

app.get('/no-permission', (req, res) => {
  res.render('no-permission', { user: req.user });
});

/* ===== PROFILE ===== */

app.get('/profile', async (req, res) => {
  if (!req.user) return res.redirect('/');

  const userRoles = await hydrateUserRoles(req.user);

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
  await hydrateUserRoles(req.user);

  const logs = await loadLogs();
  const news = await loadNews();
  const images = await loadGallery();
  const blacklist = await resolveBlacklistEntries(await loadBlacklist());
  const rules = await loadRules();
  const botConfig = await loadBotConfig();
  const syncedRoles = await loadSyncedGuildRoles();
  const syncStats = await loadDiscordSyncStats();

  let guildChannels = [];
  if (mainGuild) {
    await mainGuild.channels.fetch().catch(() => null);
    guildChannels = mainGuild.channels.cache
      .filter((channel) => channel.isTextBased?.() || channel.type === 0 || channel.type === 5)
      .map((channel) => ({
        id: channel.id,
        name: channel.name,
      }))
      .sort((a, b) => a.name.localeCompare(b.name, 'hr'));
  }

  res.render('admin', {
    user: req.user,
    logs: logs,
    news: news,                   // ⬅️ OVO MORA BITI POSLANO
    blacklist: blacklist,
    rules: rules,
    botConfig,
    guildChannels,
    syncedRoles,
    discordSync: syncStats,
    discordMembers: discordMemberCount,
    imagesCount: images.length,
    newsCount: news.length
  });

});

app.get('/bot-settings', requireAdmin, async (req, res) => {
  await hydrateUserRoles(req.user);

  const botConfig = await loadBotConfig();
  const syncedRoles = await loadSyncedGuildRoles();
  const syncStats = await loadDiscordSyncStats();

  let guildChannels = [];
  if (mainGuild) {
    await mainGuild.channels.fetch().catch(() => null);
    guildChannels = mainGuild.channels.cache
      .filter((channel) => channel.isTextBased?.() || channel.type === 0 || channel.type === 5)
      .map((channel) => ({
        id: channel.id,
        name: channel.name,
      }))
      .sort((a, b) => a.name.localeCompare(b.name, 'hr'));
  }

  res.render('bot-settings', {
    user: req.user,
    botConfig,
    guildChannels,
    syncedRoles,
    discordSync: syncStats,
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

  await logAction(`News objava dodana: "${title}"`, req.user.username);
  res.redirect('/admin');
});

app.post('/admin/news/delete/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const deleted = await deleteNewsById(id);
  if (deleted) await logAction(`News obrisan (id=${id})`, req.user.username);
  res.redirect('/admin');
});

/* ===== PRAVILA ===== */

app.get('/pravila', async (req, res) => {
  const rules = await loadRules();
  res.render('pravila', { user: req.user, rules });
});

app.post('/admin/rules', requireAdmin, async (req, res) => {
  await updateRulesMeta({
    title: (req.body.title || '').trim(),
    subtitle: (req.body.subtitle || '').trim(),
    warning: (req.body.warning || '').trim(),
  });
  await logAction('Pravila uredena', req.user.username);
  res.redirect('/admin');
});

app.post('/admin/rules/add', requireAdmin, async (req, res) => {
  const title = (req.body.ruleTitle || '').trim();
  const content = (req.body.ruleContent || '').trim();
  if (!title || !content) return res.redirect('/admin');

  await addRule(title, content);
  await logAction('Dodano novo pravilo', req.user.username, {
    title: 'Dodano novo pravilo',
    after: { title, content },
  });
  res.redirect('/admin');
});

app.post('/admin/rules/update/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const title = (req.body.ruleTitle || '').trim();
  const content = (req.body.ruleContent || '').trim();
  if (!title || !content) return res.redirect('/admin');

  const updated = await updateRuleById(id, title, content);
  if (updated) {
    await logAction('Uredeno pravilo', req.user.username, {
      title: 'Uredeno pravilo',
      before: updated.before,
      after: updated.after,
    });
  }
  res.redirect('/admin');
});

app.post('/admin/rules/delete/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const deleted = await deleteRuleById(id);
  if (deleted) {
    await logAction('Obrisano pravilo', req.user.username, {
      title: 'Obrisano pravilo',
      before: deleted,
    });
  }
  res.redirect('/admin');
});

/* ===== ADMIN: BLACKLIST ===== */

app.post('/admin/blacklist/add', requireAdmin, async (req, res) => {
  const userId = (req.body.userId || '').trim();
  if (!userId) return res.redirect('/admin');

  await addToBlacklist(userId);
  await logAction(`Blacklist ADD: ${userId}`, req.user.username);
  res.redirect('/admin');
});

app.post('/admin/blacklist/remove', requireAdmin, async (req, res) => {
  const userId = (req.body.userId || '').trim();
  if (!userId) return res.redirect('/admin');

  await removeFromBlacklist(userId);
  await logAction(`Blacklist REMOVE: ${userId}`, req.user.username);
  res.redirect('/admin');
});

app.post('/admin/bot/greetings', requireAdmin, async (req, res) => {
  const botConfig = await loadBotConfig();
  botConfig.welcome.channelId = String(req.body.welcomeChannelId || '').trim();
  botConfig.welcome.message = String(req.body.welcomeMessage || '').trim() || DEFAULT_BOT_CONFIG.welcome.message;
  await saveBotConfig(botConfig);
  await logAction('Bot postavke: welcome ažuriran', req.user.username);
  res.redirect('/admin#bot-settings');
});

app.post('/admin/bot/logging', requireAdmin, async (req, res) => {
  const botConfig = await loadBotConfig();
  botConfig.logging.channelId = String(req.body.logChannelId || '').trim();
  await saveBotConfig(botConfig);
  await logAction('Bot postavke: logging ažuriran', req.user.username);
  res.redirect('/admin#bot-settings');
});

app.post('/admin/bot/gallery', requireAdmin, async (req, res) => {
  const botConfig = await loadBotConfig();
  botConfig.gallery.channelId = String(req.body.galleryChannelId || '').trim();
  await saveBotConfig(botConfig);
  await syncGalleryFromDiscordChannel().catch(() => 0);
  await logAction('Bot postavke: gallery kanal ažuriran', req.user.username);
  res.redirect('/admin#bot-settings');
});

app.post('/admin/bot/tickets', requireAdmin, async (req, res) => {
  const botConfig = await loadBotConfig();
  const ts = botConfig.ticketSystem;

  ts.categoryId = String(req.body.ticketCategoryId || '').trim();
  ts.logChannelId = String(req.body.ticketLogChannelId || '').trim();
  ts.supportRoleId = String(req.body.ticketSupportRoleId || '').trim();
  ts.autoCloseHours = Number(req.body.autoCloseHours) || DEFAULT_BOT_CONFIG.ticketSystem.autoCloseHours;
  ts.reminderHours = Number(req.body.reminderHours) || DEFAULT_BOT_CONFIG.ticketSystem.reminderHours;
  ts.types.igranje.questions = String(req.body.igranjeQuestions || '')
    .split('\n')
    .map((q) => q.trim())
    .filter(Boolean);
  ts.types.zalba.questions = String(req.body.zalbaQuestions || '')
    .split('\n')
    .map((q) => q.trim())
    .filter(Boolean);
  ts.types.modovi.questions = String(req.body.modoviQuestions || '')
    .split('\n')
    .map((q) => q.trim())
    .filter(Boolean);
  ts.messages.reminder = String(req.body.reminderMessage || '').trim() || DEFAULT_BOT_CONFIG.ticketSystem.messages.reminder;
  ts.messages.autoClose = String(req.body.autoCloseMessage || '').trim() || DEFAULT_BOT_CONFIG.ticketSystem.messages.autoClose;

  await saveBotConfig(botConfig);
  await logAction('Bot postavke: ticket sistem ažuriran', req.user.username);
  res.redirect('/admin#bot-settings');
});

app.post('/admin/bot/embeds', requireAdmin, async (req, res) => {
  const channelId = String(req.body.embedChannelId || '').trim();
  if (!channelId) return res.redirect('/admin#bot-settings');

  const channel = await discordClient.channels.fetch(channelId).catch(() => null);
  if (!channel || !channel.isTextBased()) return res.redirect('/admin#bot-settings');

  const { EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
  const embed = new EmbedBuilder();
  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();
  const color = String(req.body.color || '').trim();
  const imageUrl = String(req.body.imageUrl || '').trim();
  const thumbnailUrl = String(req.body.thumbnailUrl || '').trim();
  const footerText = String(req.body.footerText || '').trim();
  const footerIcon = String(req.body.footerIcon || '').trim();
  const authorName = String(req.body.authorName || '').trim();
  const authorIcon = String(req.body.authorIcon || '').trim();
  const normalMessage = String(req.body.normalMessage || '').trim();
  const launcherButtonLabel = String(req.body.launcherButtonLabel || '').trim();
  const launcherButtonUrl = String(req.body.launcherButtonUrl || '').trim();

  if (title) embed.setTitle(title);
  if (description) embed.setDescription(description);
  if (color) embed.setColor(color);
  if (imageUrl) embed.setImage(imageUrl);
  if (thumbnailUrl) embed.setThumbnail(thumbnailUrl);
  if (authorName || authorIcon) {
    embed.setAuthor({ name: authorName || 'Info', iconURL: authorIcon || undefined });
  }
  if (footerText || footerIcon) {
    embed.setFooter({ text: footerText || 'Slavonska Ravnica', iconURL: footerIcon || undefined });
  }
  if (req.body.timestamp === 'on') {
    embed.setTimestamp(new Date());
  }

  const components = [];
  if (launcherButtonUrl) {
    components.push(
      new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setLabel(launcherButtonLabel || 'Otvori link')
          .setStyle(ButtonStyle.Link)
          .setURL(launcherButtonUrl)
      )
    );
  }

  await channel.send({
    content: normalMessage || undefined,
    embeds: [embed],
    components,
  });

  const botConfig = await loadBotConfig();
  botConfig.embeds.push({
    channelId,
    title,
    description,
    color,
    imageUrl,
    thumbnailUrl,
    footerText,
    footerIcon,
    authorName,
    authorIcon,
    normalMessage,
    launcherButtonLabel,
    launcherButtonUrl,
    timestamp: req.body.timestamp === 'on',
    sentAt: new Date().toISOString(),
  });
  botConfig.embeds = botConfig.embeds.slice(-20);
  await saveBotConfig(botConfig);
  await logAction('Bot postavke: embed poslan', req.user.username);
  res.redirect('/admin#bot-settings');
});

app.post('/admin/discord-sync', requireAdmin, async (req, res) => {
  await syncDiscordStateToDatabase().catch((err) => {
    console.log('MANUAL DISCORD SYNC ERROR:', err.message);
  });
  await syncGalleryFromDiscordChannel().catch((err) => {
    console.log('MANUAL GALLERY SYNC ERROR:', err.message);
  });
  await logAction('Discord sinkronizacija pokrenuta ručno', req.user.username);
  res.redirect('/admin#bot-settings');
});

/* ===== STATISTIKA ===== */

app.get('/statistika', async (req, res) => {
  let stats = {
    serverStatus: 'Offline',
    playersOnline: 0,
    maxPlayers: 16,
    totalPlayers: 0,
    onlinePlayers: [],
    discordMembers: discordMemberCount,
    totalFarms: 0,
    totalFields: 0,
    totalVehicles: 0,
    totalSilos: 0,
    totalProductions: 0,
    totalAnimals: 0,
    totalArea: 0,
    mapName: null,
    modCount: null,
    serverName: null,
    farms: [],
  };

  try {
    // Try G-Portal / Steam Query first
    const playerStats = await getPlayerStats();
    stats.serverStatus = playerStats.serverStatus;
    stats.playersOnline = playerStats.playersOnline;
    stats.maxPlayers = playerStats.maxPlayers;
  } catch (e) {}

  try {
    // Enrich with MongoDB data
    const db = await getBotDb();
    if (db) {
      const allPlayers = await db.collection('players').find().toArray();
      const allFarms = await db.collection('farms').find().toArray();
      const allFields = await db.collection('fields').find().toArray();
      const allVehicles = await db.collection('vehicles').find().toArray();
      const allSilos = await db.collection('silos').find().toArray();
      const allProductions = await db.collection('productions').find().toArray();
      const allAnimals = await db.collection('animals').find().toArray();

      const online = allPlayers.filter(p => !!p.isOnline);
      stats.totalPlayers = allPlayers.length;
      stats.onlinePlayers = online.map(p => ({ name: p.name, farmId: p.farmId }));

      const activeFarms = allFarms.filter(f => f.farmId && !String(f.farmId).startsWith('U:'));
      stats.totalFarms = activeFarms.length;
      stats.totalFields = allFields.length;
      stats.totalVehicles = allVehicles.length;
      stats.totalSilos = allSilos.length;
      stats.totalProductions = allProductions.length;
      stats.totalAnimals = allAnimals.reduce((sum, a) => sum + (a.numAnimals || 0), 0);
      stats.totalArea = allFields.reduce((sum, f) => sum + (parseFloat(f.fieldArea) || 0), 0);

      // Farm details for the overview
      stats.farms = activeFarms.map(farm => {
        const fid = String(farm.farmId);
        const farmPlayers = allPlayers.filter(p => String(p.farmId) === fid);
        const farmFields = allFields.filter(f => String(f.ownerFarmId) === fid);
        return {
          farmId: farm.farmId,
          name: farm.name || ('Farma ' + farm.farmId),
          balance: Math.round(farm.balance || 0),
          playerCount: farmPlayers.length,
          fieldCount: farmFields.length,
          vehicleCount: allVehicles.filter(v => String(v.farmId) === fid).length,
        };
      }).sort((a, b) => Number(a.farmId) - Number(b.farmId));

      // If G-Portal didn't work, use MongoDB online count
      if (stats.serverStatus === 'Offline' || stats.playersOnline === '-') {
        if (online.length > 0) {
          stats.serverStatus = 'Online';
          stats.playersOnline = online.length;
        }
        if (stats.maxPlayers === '-' || stats.maxPlayers === 0) {
          stats.maxPlayers = allPlayers.length || 16;
        }
      }

      // Read server_info stored by farmbuddy bot (map name, mod count)
      try {
        const serverInfo = await db.collection('server_info').findOne({});
        if (serverInfo) {
          if (serverInfo.mapName) stats.mapName = serverInfo.mapName;
          if (serverInfo.modCount) stats.modCount = serverInfo.modCount;
          if (serverInfo.serverName) stats.serverName = serverInfo.serverName;
          if (serverInfo.isOnline != null && stats.serverStatus === 'Offline') {
            stats.serverStatus = serverInfo.isOnline ? 'Online' : 'Offline';
          }
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('[STATISTIKA] MongoDB error:', e.message);
  }

  res.render('statistika', { user: req.user, stats });
});

/* ===== GALERIJA ===== */

app.get('/moja-farma', async (req, res) => {
  let farmData = null;

  if (req.user) {
    try {
      const db = await getBotDb();

      if (!db) {
        console.log('[MOJA-FARMA] Bot database not available');
      } else {
        console.log('[MOJA-FARMA] Querying for Discord user:', req.user.id, '(' + req.user.username + ')');

        // Find player link by Discord user ID
        const playerLink = await db.collection('player_links').findOne({ discordUserId: req.user.id });
        console.log('[MOJA-FARMA] Player link:', JSON.stringify(playerLink, null, 2));

        // Even without a player_link, try to find farm data
        let farmId = playerLink ? playerLink.defaultFarmId : null;

        // Fallback 1: find farm via players collection using uniqueUserId
        if (!farmId && playerLink && playerLink.uniqueUserId) {
          console.log('[MOJA-FARMA] Fallback 1: searching players by uniqueUserId:', playerLink.uniqueUserId);
          const player = await db.collection('players').findOne({ uniqueUserId: playerLink.uniqueUserId });
          if (player && player.farmId) {
            farmId = player.farmId;
            console.log('[MOJA-FARMA] Fallback 1 success: farmId =', farmId);
          } else {
            console.log('[MOJA-FARMA] Fallback 1: no player found or no farmId');
          }
        }

        // Fallback 2: match playerName to farm name
        if (!farmId && playerLink && playerLink.playerName) {
          console.log('[MOJA-FARMA] Fallback 2: matching playerName to farm name:', playerLink.playerName);
          const allFarms = await db.collection('farms').find().toArray();
          console.log('[MOJA-FARMA] Available farms:', allFarms.map(f => ({ farmId: f.farmId, name: f.name })));
          const matchedFarm = allFarms.find(f => f.name && f.name.trim().toLowerCase() === playerLink.playerName.trim().toLowerCase());
          if (matchedFarm) {
            farmId = matchedFarm.farmId;
            console.log('[MOJA-FARMA] Fallback 2 success: matched farm by name, farmId =', farmId);
          }
        }

        // Fallback 3: use first available non-wallet farm
        if (!farmId) {
          console.log('[MOJA-FARMA] Fallback 3: using first available farm...');
          const allFarms = await db.collection('farms').find().toArray();
          const realFarm = allFarms.find(f => f.farmId && !String(f.farmId).startsWith('U:'));
          if (realFarm) {
            farmId = realFarm.farmId;
            console.log('[MOJA-FARMA] Fallback 3 success: using farmId =', farmId);
          }
        }

        if (farmId) {
          const farm = await db.collection('farms').findOne({ farmId });
          console.log('[MOJA-FARMA] Farm found:', farm ? farm.name : 'NONE');

          if (farm) {
            const [fields, vehicles, silos, productions, animals, players] = await Promise.all([
              db.collection('fields').find({ ownerFarmId: farmId }).toArray(),
              db.collection('vehicles').find({ farmId }).toArray(),
              db.collection('silos').find({ farmId }).toArray(),
              db.collection('productions').find({ farmId }).toArray(),
              db.collection('animals').find({ farmId }).toArray(),
              db.collection('players').find({ farmId }).toArray(),
            ]);

            console.log('[MOJA-FARMA] Data counts - fields:', fields.length, 'vehicles:', vehicles.length, 'silos:', silos.length, 'productions:', productions.length, 'animals:', animals.length, 'players:', players.length);

            farmData = {
              farmId: farm.farmId,
              name: farm.name || ('Farma ' + farm.farmId),
              balance: farm.balance || 0,
              fields,
              vehicles,
              silos,
              productions,
              animals,
              players,
            };
          }
        }

        // Fetch all farms for transfer dropdown (exclude current farm)
        var allFarmsForTransfer = [];
        try {
          const allF = await db.collection('farms').find().toArray();
          allFarmsForTransfer = allF
            .filter(f => f.farmId && !String(f.farmId).startsWith('U:') && String(f.farmId) !== String(farmId))
            .map(f => ({ farmId: f.farmId, name: f.name || ('Farma ' + f.farmId) }));
        } catch(e) {}
      }
    } catch (err) {
      console.error('[MOJA-FARMA] Greška pri dohvaćanju farme:', err.message);
    }
  }

  res.render('moja-farma', { user: req.user, farm: farmData, otherFarms: allFarmsForTransfer || [] });
});

app.get('/galerija', async (req, res) => {
  let roles = [];
  let canUpload = false;
  let isAdmin = false;
  let uploadBlocked = false;

  if (req.user) {
    roles = await hydrateUserRoles(req.user);
    canUpload = canUploadWithRoles(req.user, roles);
    isAdmin = isGalleryAdminByRoles(roles);
    uploadBlocked = await isBlacklisted(req.user.id);
  }

  const gallery = await loadGallery(req.user?.id || '');
  const openImage = String(req.query.open || '').trim();
  const uploadNotice = String(req.query.uploadNotice || '').trim();

  res.render('galerija', {
    user: req.user,
    gallery,
    canUpload,
    uploadBlocked,
    uploadNotice,
    isAdmin,
    openImage,
  });
});

app.get('/api/gallery/status', async (req, res) => {
  const gallery = await loadGallery(req.user?.id || '');
  const latest = gallery.length
    ? Math.max(...gallery.map((img) => Number(img.uploadedAtMs || 0)))
    : 0;

  res.json({
    count: gallery.length,
    latestUploadedAtMs: latest,
  });
});

/* ===== UPLOAD (PLAYER+) ===== */

app.post('/upload', async (req, res) => {
  if (!req.user) return res.redirect('/');

  if (await isBlacklisted(req.user.id)) {
    return res.redirect('/galerija?uploadNotice=blocked');
  }

  const roles = req.user.roles?.length ? req.user.roles : await getMemberRoles(req.user.id);
  const canUpload = canUploadWithRoles(req.user, roles);

  if (!canUpload) return res.redirect('/no-permission');

  upload.single('image')(req, res, async function (err) {
    if (err) return res.send('Greška.');
    try {
      const description = String(req.body.description || '').trim().slice(0, 500);
      const filename = `${Date.now()}-${String(req.file.originalname || 'image').replace(/\s+/g, '-')}`;
      const localPath = path.join(uploadPath, filename);
      if (!useMySql || !dbPool) {
        fs.writeFileSync(localPath, req.file.buffer);
      }
      await addGalleryImage({
        filename,
        uploaderId: req.user.id,
        uploaderName: req.user.username,
        uploaderAvatar: req.user.avatar,
        description,
        mimeType: req.file.mimetype,
        imageData: req.file.buffer,
        reactions: { like: 0, heart: 0, sr: 0 },
      });
      await publishGalleryImageToDiscord(
        {
          filename,
          uploaderName: req.user.username,
          description,
        },
        req.file.buffer
      );
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

function getGalleryRedirectTarget(req, filename) {
  const redirectTo = String(req.body.returnTo || '').trim();
  if (redirectTo.startsWith('/galerija')) return redirectTo;
  if (filename) return `/galerija?open=${encodeURIComponent(filename)}`;
  return '/galerija';
}

app.post('/comment/:image', async (req, res) => {
  if (!req.user) return res.redirect('/');

  if (await isBlacklisted(req.user.id)) {
    return res.send('Blokiran si za komentare.');
  }

  const text = sanitizeComment(req.body.comment);

  if (!text.trim()) return res.redirect(getGalleryRedirectTarget(req, req.params.image));
  const added = await addGalleryComment(req.params.image, {
    user: req.user.username,
    text,
    date: new Date().toLocaleString(),
  });
  if (!added) return res.redirect(getGalleryRedirectTarget(req, req.params.image));
  res.redirect(getGalleryRedirectTarget(req, req.params.image));
});

app.post('/react/:image', async (req, res) => {
  if (!req.user) return res.redirect('/');

  if (await isBlacklisted(req.user.id)) {
    return res.send('Blokiran si za reakcije.');
  }

  const reactionType = String(req.body.reaction || '').trim();
  const added = await toggleGalleryReaction(req.params.image, req.user.id, reactionType);
  if (!added) return res.redirect(getGalleryRedirectTarget(req, req.params.image));
  res.redirect(getGalleryRedirectTarget(req, req.params.image));
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

    await logAction(`Obrisana slika: ${filename}`, req.user.username);
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
      const roles = await hydrateUserRoles(req.user);
      req.user.roles = roles;
    } catch (err) {
      console.log('ROLE FETCH ERROR:', err.message);
      req.user.roles = [];
    }

    await sendWebLoginDiscordLog(req.user);

    res.redirect('/');
  }
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

/* ===== MONEY TRANSFER API ===== */

// Create a pending transfer
app.post('/api/money-transfer', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Niste prijavljeni' });
  try {
    const db = await getBotDb();
    if (!db) return res.status(500).json({ error: 'Baza nedostupna' });

    const { fromFarmId, toFarmId, amount } = req.body;
    const transferAmount = parseInt(amount);

    if (!fromFarmId || !toFarmId || !transferAmount || transferAmount < 1) {
      return res.status(400).json({ error: 'Neispravan zahtjev' });
    }
    if (String(fromFarmId) === String(toFarmId)) {
      return res.status(400).json({ error: 'Ne možete slati novac na istu farmu' });
    }

    // Verify user owns the source farm (same fallback chain as moja-farma)
    const playerLink = await db.collection('player_links').findOne({ discordUserId: req.user.id });
    if (!playerLink) return res.status(403).json({ error: 'Nemate povezan račun' });

    let userFarmId = playerLink.defaultFarmId;

    // Fallback 1: find farm via players collection using uniqueUserId
    if (!userFarmId && playerLink.uniqueUserId) {
      const player = await db.collection('players').findOne({ uniqueUserId: playerLink.uniqueUserId });
      if (player && player.farmId) userFarmId = player.farmId;
    }

    // Fallback 2: match playerName to farm name
    if (!userFarmId && playerLink.playerName) {
      const allFarms = await db.collection('farms').find().toArray();
      const matchedFarm = allFarms.find(f => f.name && f.name.trim().toLowerCase() === playerLink.playerName.trim().toLowerCase());
      if (matchedFarm) userFarmId = matchedFarm.farmId;
    }

    // Fallback 3: use the fromFarmId if user has a valid player_link (they are authenticated)
    if (!userFarmId && playerLink) {
      userFarmId = fromFarmId;
    }

    if (String(userFarmId) !== String(fromFarmId)) {
      return res.status(403).json({ error: 'Nemate pristup ovoj farmi' });
    }

    // Check balance
    const fromFarm = await db.collection('farms').findOne({ farmId: String(fromFarmId) });
    if (!fromFarm || (fromFarm.balance || 0) < transferAmount) {
      return res.status(400).json({ error: 'Nedovoljno sredstava na računu' });
    }

    // Get target farm name
    const toFarm = await db.collection('farms').findOne({ farmId: String(toFarmId) });
    const toFarmName = toFarm ? toFarm.name : ('Farma ' + toFarmId);

    // Check total pending doesn't exceed balance
    const pendingTotal = await db.collection('pending_transfers').aggregate([
      { $match: { fromFarmId: String(fromFarmId), status: 'pending' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]).toArray();
    const alreadyPending = pendingTotal.length > 0 ? pendingTotal[0].total : 0;

    if (alreadyPending + transferAmount > (fromFarm.balance || 0)) {
      return res.status(400).json({ error: 'Ukupni zakazani prijenosi premašuju stanje računa' });
    }

    await db.collection('pending_transfers').insertOne({
      fromFarmId: String(fromFarmId),
      toFarmId: String(toFarmId),
      toFarmName,
      amount: transferAmount,
      requestedBy: req.user.id,
      requestedByName: req.user.username,
      status: 'pending',
      createdAt: new Date()
    });

    res.json({ success: true, message: 'Prijenos od ' + transferAmount.toLocaleString('hr-HR') + ' € zakazan za ' + toFarmName });
  } catch (err) {
    console.error('[TRANSFER] Error:', err.message);
    res.status(500).json({ error: 'Greška na serveru' });
  }
});

// Get pending transfers for current user
app.get('/api/money-transfer/pending', async (req, res) => {
  if (!req.user) return res.status(401).json({ transfers: [] });
  try {
    const db = await getBotDb();
    if (!db) return res.json({ transfers: [] });

    const playerLink = await db.collection('player_links').findOne({ discordUserId: req.user.id });
    if (!playerLink) return res.json({ transfers: [] });

    let userFarmId = playerLink.defaultFarmId;
    if (!userFarmId && playerLink.uniqueUserId) {
      const player = await db.collection('players').findOne({ uniqueUserId: playerLink.uniqueUserId });
      if (player) userFarmId = player.farmId;
    }
    if (!userFarmId) return res.json({ transfers: [] });

    const transfers = await db.collection('pending_transfers')
      .find({ fromFarmId: String(userFarmId), status: 'pending' })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ transfers });
  } catch (err) {
    console.error('[TRANSFER] Pending error:', err.message);
    res.json({ transfers: [] });
  }
});

// Cancel a pending transfer
app.delete('/api/money-transfer/:id', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Niste prijavljeni' });
  try {
    const db = await getBotDb();
    if (!db) return res.status(500).json({ error: 'Baza nedostupna' });

    const { ObjectId } = require('mongodb');
    let objId;
    try { objId = new ObjectId(req.params.id); } catch(e) {
      return res.status(400).json({ error: 'Neispravan ID' });
    }

    const transfer = await db.collection('pending_transfers').findOne({ _id: objId });
    if (!transfer) return res.status(404).json({ error: 'Prijenos nije pronađen' });
    if (transfer.requestedBy !== req.user.id) {
      return res.status(403).json({ error: 'Nemate pristup' });
    }
    if (transfer.status !== 'pending') {
      return res.status(400).json({ error: 'Prijenos je već obrađen' });
    }

    await db.collection('pending_transfers').updateOne(
      { _id: objId },
      { $set: { status: 'cancelled', cancelledAt: new Date() } }
    );

    res.json({ success: true });
  } catch (err) {
    console.error('[TRANSFER] Cancel error:', err.message);
    res.status(500).json({ error: 'Greška na serveru' });
  }
});

/* ===== START ===== */

const PORT = Number(process.env.PORT) || 3000;
initMySql().finally(() => {
  app.listen(PORT, () => console.log('FS25 Web pokrenut na portu ' + PORT));
});

