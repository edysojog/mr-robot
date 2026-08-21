const { ipcMain } = require('electron');
const { CHANNELS } = require('../../shared/types');
const localSettings = require('../services/localSettings');
const secureStore = require('../services/secureStore');
const chatService = require('../services/chatService');

// secureStore keys providers by their SDK name, not the localSettings
// provider id -- 'claude' in settings is 'anthropic' in secureStore, same
// mapping scanHandlers.js/settingsHandlers.js already rely on.
const SECURE_STORE_KEY = { claude: 'anthropic', groq: 'groq', gemini: 'gemini', openai: 'openai' };

function registerChatHandlers() {
  ipcMain.handle(CHANNELS.FINDING_CHAT, async (event, rootDir, finding, history, question) => {
    if (typeof question !== 'string' || !question.trim()) {
      throw new Error('Question must be a non-empty string.');
    }

    const provider = localSettings.getProvider();
    const secureKey = SECURE_STORE_KEY[provider];
    if (!localSettings.KEYLESS_PROVIDERS.includes(provider) && !secureStore.hasApiKey(secureKey)) {
      throw new Error(`No ${provider} API key set. Add one in Settings, or switch to mock mode, before asking about a finding.`);
    }

    const apiKey = localSettings.KEYLESS_PROVIDERS.includes(provider) ? null : secureStore.getApiKey(secureKey);
    const model = localSettings.getProviderModel(provider);
    const ollamaBaseUrl = localSettings.getOllamaBaseUrl();

    const answer = await chatService.chat({
      provider,
      apiKey,
      model,
      ollamaBaseUrl,
      rootDir,
      finding,
      history,
      question: question.trim(),
    });

    return { answer };
  });
}

module.exports = { registerChatHandlers };
