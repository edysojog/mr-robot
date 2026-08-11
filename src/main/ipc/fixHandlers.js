const { ipcMain } = require('electron');
const { CHANNELS } = require('../../shared/types');
const secureStore = require('../services/secureStore');
const localSettings = require('../services/localSettings');
const fixAdvisor = require('../services/fixAdvisor');

// Claude's stored key is kept under "anthropic" for backward compat (see
// the same mapping in folderSelect.js's PROVIDER_KEY_INFO) -- every other
// provider's secureStore key matches its localSettings provider name.
function secureStoreKeyFor(provider) {
  return provider === 'claude' ? 'anthropic' : provider;
}

function registerFixHandlers() {
  ipcMain.handle(CHANNELS.FIX_SUGGEST, async (event, rootDir, finding) => {
    const provider = localSettings.getProvider();

    if (!localSettings.KEYLESS_PROVIDERS.includes(provider) && provider !== 'mock' && !secureStore.hasApiKey(secureStoreKeyFor(provider))) {
      throw new Error(`No ${provider} API key set. Add one in Settings before requesting a fix.`);
    }

    const apiKey = provider === 'mock' || localSettings.KEYLESS_PROVIDERS.includes(provider)
      ? null
      : secureStore.getApiKey(secureStoreKeyFor(provider));

    return fixAdvisor.suggestFix({
      provider,
      apiKey,
      model: localSettings.getProviderModel(provider),
      ollamaBaseUrl: localSettings.getOllamaBaseUrl(),
      rootDir,
      finding,
    });
  });
}

module.exports = { registerFixHandlers };
