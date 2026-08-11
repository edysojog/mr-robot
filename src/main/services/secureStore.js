const fs = require('fs');
const path = require('path');
const { app, safeStorage } = require('electron');

// 'anthropic' keeps the original filename for backward compat with keys
// saved before multi-provider support existed; other providers get their
// own file.
function keyFilePath(provider) {
  const filename = provider === 'anthropic' ? 'apikey.enc' : `apikey-${provider}.enc`;
  return path.join(app.getPath('userData'), filename);
}

function isAvailable() {
  return safeStorage.isEncryptionAvailable();
}

function saveApiKey(provider, plainTextKey) {
  if (!isAvailable()) {
    throw new Error('OS-level encryption is not available on this machine; refusing to store the API key.');
  }
  const encrypted = safeStorage.encryptString(plainTextKey);
  fs.writeFileSync(keyFilePath(provider), encrypted);
}

function hasApiKey(provider) {
  return fs.existsSync(keyFilePath(provider));
}

function getApiKey(provider) {
  if (!hasApiKey(provider)) return null;
  if (!isAvailable()) {
    throw new Error('OS-level encryption is not available on this machine; cannot decrypt the stored API key.');
  }
  const encrypted = fs.readFileSync(keyFilePath(provider));
  return safeStorage.decryptString(encrypted);
}

function clearApiKey(provider) {
  if (hasApiKey(provider)) {
    fs.unlinkSync(keyFilePath(provider));
  }
}

module.exports = { isAvailable, saveApiKey, hasApiKey, getApiKey, clearApiKey };
