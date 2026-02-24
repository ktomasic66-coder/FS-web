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

async function getStatsFromApi() {
  const url = process.env.PLAYER_API_URL;
  if (!url) return null;

  const timeoutMs = Number(process.env.PLAYER_API_TIMEOUT_MS || 3500);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) return null;
    const payload = await response.json();
    return fromPayload(payload);
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
  if (apiStats) return apiStats;

  const steamStats = await getStatsFromSteamQuery();
  if (steamStats) return steamStats;

  return { ...FALLBACK };
}

module.exports = { getPlayerStats };
