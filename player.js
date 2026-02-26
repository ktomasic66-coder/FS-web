const fetch = require('node-fetch');
const { queryGameServerInfo } = require('steam-server-query');

const FALLBACK = {
  serverStatus: 'Offline',
  playersOnline: '-',
  maxPlayers: '-',
};

function toValidCount(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) return null;
  return Math.floor(num);
}

function fromPayload(payload) {
  if (!payload || typeof payload !== 'object') return null;

  const players = toValidCount(payload.playersOnline ?? payload.players ?? payload.playerCount);
  const maxPlayers = toValidCount(payload.maxPlayers ?? payload.max ?? payload.slots);
  const isOnline = payload.online ?? payload.serverOnline ?? true;

  if (players === null || maxPlayers === null) return null;

  return {
    serverStatus: isOnline ? 'Online' : 'Offline',
    playersOnline: players,
    maxPlayers: maxPlayers,
  };
}

function pickXmlValue(xmlText, keys) {
  for (const key of keys) {
    const pattern = new RegExp(`<${key}>([^<]+)</${key}>`, 'i');
    const match = xmlText.match(pattern);
    if (match && match[1]) return match[1].trim();
  }
  return null;
}

function fromXml(xmlText) {
  if (!xmlText || typeof xmlText !== 'string') return null;

  const playersRaw = pickXmlValue(xmlText, [
    'players',
    'numplayers',
    'player_count',
    'currentplayers',
    'players_online',
  ]);
  const maxPlayersRaw = pickXmlValue(xmlText, [
    'maxplayers',
    'max_players',
    'slots',
    'maxplayer',
    'player_slots',
  ]);
  const statusRaw = pickXmlValue(xmlText, ['status', 'online']);

  const players = toValidCount(playersRaw);
  const parsedMaxPlayers = toValidCount(maxPlayersRaw);
  let maxPlayers = parsedMaxPlayers;
  const fallbackMax = toValidCount(process.env.DEFAULT_MAX_PLAYERS || process.env.MAX_PLAYERS);

  if (maxPlayers === null || maxPlayers === 0) {
    if (fallbackMax !== null && fallbackMax > 0) maxPlayers = fallbackMax;
  }

  if (players === null || maxPlayers === null) return null;

  let isOnline = true;
  if (statusRaw) {
    const normalized = String(statusRaw).toLowerCase();
    isOnline = !['0', 'false', 'offline'].includes(normalized);
  } else {
    // If API does not include a status flag, treat 0/0 as offline.
    isOnline = !(players === 0 && (parsedMaxPlayers === 0 || parsedMaxPlayers === null));
  }

  return {
    serverStatus: isOnline ? 'Online' : 'Offline',
    playersOnline: players,
    maxPlayers: maxPlayers,
  };
}

async function getStatsFromApi() {
  const url = process.env.PLAYER_API_URL;
  if (!url) return null;

  const timeoutMs = Number(process.env.PLAYER_API_TIMEOUT_MS || 3500);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) return null;
    const bodyText = await response.text();

    try {
      const payload = JSON.parse(bodyText);
      return fromPayload(payload);
    } catch {
      return fromXml(bodyText);
    }
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function getStatsFromXmlApi() {
  const url = process.env.GPORTAL_XML_URL || process.env.PLAYER_XML_URL;
  if (!url) return null;

  const timeoutMs = Number(process.env.PLAYER_API_TIMEOUT_MS || 3500);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) return null;
    const xmlText = await response.text();
    return fromXml(xmlText);
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function getStatsFromSteamQuery() {
  const serverAddress =
    process.env.GAME_SERVER_ADDRESS ||
    process.env.GPORTAL_SERVER_ADDRESS ||
    process.env.STEAM_SERVER_ADDRESS;

  if (!serverAddress) return null;

  try {
    const info = await queryGameServerInfo(serverAddress, 1, 3000);
    const players = toValidCount(info.players);
    const maxPlayers = toValidCount(info.maxPlayers);
    if (players === null || maxPlayers === null) return null;

    return {
      serverStatus: 'Online',
      playersOnline: players,
      maxPlayers: maxPlayers,
    };
  } catch {
    return null;
  }
}

async function getPlayerStats() {
  const apiStats = await getStatsFromApi();
  if (apiStats) {
    console.log('[stats] source=PLAYER_API_URL');
    return apiStats;
  }

  const xmlStats = await getStatsFromXmlApi();
  if (xmlStats) {
    console.log('[stats] source=GPORTAL_XML_URL');
    return xmlStats;
  }

  const steamStats = await getStatsFromSteamQuery();
  if (steamStats) {
    console.log('[stats] source=STEAM_QUERY');
    return steamStats;
  }

  console.log('[stats] source=FALLBACK');

  return { ...FALLBACK };
}

module.exports = { getPlayerStats };
