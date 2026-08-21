const fs = require('fs');
const path = require('path');
const { app } = require('electron');

// Plain-JSON store for non-secret settings. The API key never goes here --
// that's secureStore.js, backed by safeStorage encryption.
function settingsFilePath() {
  return path.join(app.getPath('userData'), 'settings.json');
}

function readAll() {
  try {
    return JSON.parse(fs.readFileSync(settingsFilePath(), 'utf8'));
  } catch {
    return {};
  }
}

function writeAll(settings) {
  fs.writeFileSync(settingsFilePath(), JSON.stringify(settings, null, 2));
}

// mock is still a valid CLI provider (src/cli/index.js has its own
// KEYLESS_PROVIDERS) but isn't offered as a GUI choice -- not selectable
// via Settings/onboarding, so it's left out of this list.
const PROVIDERS = ['groq', 'claude', 'gemini', 'openai', 'deepseek', 'ollama'];
const DEFAULT_PROVIDER = 'groq';
// ollama needs no key (local, unauthenticated by default) -- every other
// GUI-selectable provider does.
const KEYLESS_PROVIDERS = ['ollama'];

function getProvider() {
  const settings = readAll();
  if (PROVIDERS.includes(settings.provider)) return settings.provider;
  return DEFAULT_PROVIDER;
}

function setProvider(value) {
  if (!PROVIDERS.includes(value)) {
    throw new Error(`Unsupported provider: ${value}`);
  }
  const settings = readAll();
  settings.provider = value;
  writeAll(settings);
}

// Free-text per-provider model override, not an enum -- unlike Claude's
// small fixed set, Gemini/OpenAI/Ollama model catalogs change too often
// (and Ollama's valid set is whatever the user has locally pulled) to
// safely hardcode a restricted list. Each auditor already falls back to
// its own DEFAULT_MODEL when this is unset, so an empty override is valid.
function getProviderModel(provider) {
  const models = readAll().providerModels;
  const value = models && models[provider];
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function setProviderModel(provider, value) {
  const settings = readAll();
  if (!settings.providerModels) settings.providerModels = {};
  const trimmed = (value || '').trim();
  if (trimmed) {
    settings.providerModels[provider] = trimmed;
  } else {
    delete settings.providerModels[provider];
  }
  writeAll(settings);
}

const DEFAULT_OLLAMA_BASE_URL = 'http://localhost:11434/v1';

function getOllamaBaseUrl() {
  const url = readAll().ollamaBaseUrl;
  return typeof url === 'string' && url.trim() ? url.trim() : DEFAULT_OLLAMA_BASE_URL;
}

function setOllamaBaseUrl(value) {
  const settings = readAll();
  const trimmed = (value || '').trim();
  settings.ollamaBaseUrl = trimmed || DEFAULT_OLLAMA_BASE_URL;
  writeAll(settings);
}

function getVerificationEnabled() {
  const settings = readAll();
  return settings.verificationEnabled !== false; // default on
}

function setVerificationEnabled(value) {
  const settings = readAll();
  settings.verificationEnabled = !!value;
  writeAll(settings);
}

function getReconEnabled() {
  const settings = readAll();
  return settings.reconEnabled !== false; // default on
}

function setReconEnabled(value) {
  const settings = readAll();
  settings.reconEnabled = !!value;
  writeAll(settings);
}

// Off by default -- unlike recon/verification (one extra call per scan/batch),
// specialist mode multiplies the scanner call count by SPECIALISTS.length
// per batch, a real cost jump that should be an explicit opt-in.
function getSpecialistsEnabled() {
  const settings = readAll();
  return settings.specialistsEnabled === true;
}

function setSpecialistsEnabled(value) {
  const settings = readAll();
  settings.specialistsEnabled = !!value;
  writeAll(settings);
}

// Drives first-run routing: false until the user has been through the
// provider-setup screen once, at which point the app stops opening there
// automatically and goes straight to the folder picker like normal.
function getSetupComplete() {
  return readAll().setupComplete === true;
}

function setSetupComplete(value) {
  const settings = readAll();
  settings.setupComplete = !!value;
  writeAll(settings);
}

const MAX_RECENT_FOLDERS = 8;

function getRecentFolders() {
  const list = readAll().recentFolders;
  return Array.isArray(list) ? list : [];
}

function addRecentFolder(folderPath) {
  const settings = readAll();
  const existing = Array.isArray(settings.recentFolders) ? settings.recentFolders : [];
  const deduped = [folderPath, ...existing.filter((p) => p !== folderPath)];
  settings.recentFolders = deduped.slice(0, MAX_RECENT_FOLDERS);
  writeAll(settings);
}

function removeRecentFolder(folderPath) {
  const settings = readAll();
  const existing = Array.isArray(settings.recentFolders) ? settings.recentFolders : [];
  settings.recentFolders = existing.filter((p) => p !== folderPath);
  writeAll(settings);
}

module.exports = {
  PROVIDERS,
  DEFAULT_PROVIDER,
  KEYLESS_PROVIDERS,
  getProvider,
  setProvider,
  getProviderModel,
  setProviderModel,
  DEFAULT_OLLAMA_BASE_URL,
  getOllamaBaseUrl,
  setOllamaBaseUrl,
  getRecentFolders,
  addRecentFolder,
  removeRecentFolder,
  getVerificationEnabled,
  setVerificationEnabled,
  getReconEnabled,
  setReconEnabled,
  getSpecialistsEnabled,
  setSpecialistsEnabled,
  getSetupComplete,
  setSetupComplete,
};
