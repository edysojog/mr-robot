const { ipcMain } = require('electron');
const Anthropic = require('@anthropic-ai/sdk');
const Groq = require('groq-sdk');
const OpenAI = require('openai');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { CHANNELS } = require('../../shared/types');
const secureStore = require('../services/secureStore');
const semgrepRunner = require('../services/semgrepRunner');
const gitleaksRunner = require('../services/gitleaksRunner');
const npmAuditRunner = require('../services/npmAuditRunner');
const localSettings = require('../services/localSettings');
const { DEFAULT_MODEL: DEFAULT_GROQ_MODEL } = require('../services/groqAuditor');
const { DEFAULT_MODEL: DEFAULT_GEMINI_MODEL } = require('../services/geminiAuditor');
const { DEFAULT_MODEL: DEFAULT_OPENAI_MODEL } = require('../services/openaiAuditor');
const { DEFAULT_MODEL: DEFAULT_OLLAMA_MODEL } = require('../services/ollamaAuditor');
const { DEFAULT_MODEL: DEFAULT_DEEPSEEK_MODEL, BASE_URL: DEEPSEEK_BASE_URL } = require('../services/deepseekAuditor');

// Providers a stored API key applies to -- mock and ollama are excluded
// (localSettings.KEYLESS_PROVIDERS), so there's nothing to report for them.
const KEYED_PROVIDERS = ['anthropic', 'groq', 'gemini', 'openai', 'deepseek'];

function registerSettingsHandlers() {
  ipcMain.handle(CHANNELS.SETTINGS_GET, async () => {
    const hasKeys = {};
    KEYED_PROVIDERS.forEach((p) => { hasKeys[p] = secureStore.hasApiKey(p); });

    const providerModels = {};
    localSettings.PROVIDERS.forEach((p) => { providerModels[p] = localSettings.getProviderModel(p); });

    return {
      hasKeys,
      encryptionAvailable: secureStore.isAvailable(),
      provider: localSettings.getProvider(),
      providerModels,
      ollamaBaseUrl: localSettings.getOllamaBaseUrl(),
      recentFolders: localSettings.getRecentFolders(),
      verificationEnabled: localSettings.getVerificationEnabled(),
      reconEnabled: localSettings.getReconEnabled(),
      specialistsEnabled: localSettings.getSpecialistsEnabled(),
      setupComplete: localSettings.getSetupComplete(),
    };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SET_SETUP_COMPLETE, async (event, value) => {
    localSettings.setSetupComplete(value);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SET_PROVIDER, async (event, provider) => {
    localSettings.setProvider(provider);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SET_MODEL, async (event, provider, model) => {
    localSettings.setProviderModel(provider, model);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SET_OLLAMA_URL, async (event, url) => {
    localSettings.setOllamaBaseUrl(url);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SET_VERIFICATION, async (event, enabled) => {
    localSettings.setVerificationEnabled(enabled);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SET_RECON, async (event, enabled) => {
    localSettings.setReconEnabled(enabled);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SET_SPECIALISTS, async (event, enabled) => {
    localSettings.setSpecialistsEnabled(enabled);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_TEST_KEY, async (event, provider) => {
    // Ollama needs no stored key (local, unauthenticated) -- everything
    // else does, and there's nothing to test without one.
    if (provider !== 'ollama' && !secureStore.hasApiKey(provider)) {
      throw new Error('No API key saved yet.');
    }
    const apiKey = provider === 'ollama' ? null : secureStore.getApiKey(provider);

    // Cheapest possible real request for each provider: 1 max_tokens, tiny prompt.
    if (provider === 'anthropic') {
      const client = new Anthropic({ apiKey });
      await client.messages.create({
        model: localSettings.getProviderModel('claude') || 'claude-sonnet-5',
        max_tokens: 1,
        messages: [{ role: 'user', content: 'hi' }],
      });
    } else if (provider === 'groq') {
      const client = new Groq({ apiKey });
      await client.chat.completions.create({
        model: localSettings.getProviderModel('groq') || DEFAULT_GROQ_MODEL,
        max_tokens: 1,
        messages: [{ role: 'user', content: 'hi' }],
      });
    } else if (provider === 'gemini') {
      const client = new GoogleGenerativeAI(apiKey);
      const model = client.getGenerativeModel({ model: localSettings.getProviderModel('gemini') || DEFAULT_GEMINI_MODEL });
      await model.generateContent({ contents: [{ role: 'user', parts: [{ text: 'hi' }] }], generationConfig: { maxOutputTokens: 1 } });
    } else if (provider === 'openai') {
      const client = new OpenAI({ apiKey });
      await client.chat.completions.create({
        model: localSettings.getProviderModel('openai') || DEFAULT_OPENAI_MODEL,
        max_tokens: 1,
        messages: [{ role: 'user', content: 'hi' }],
      });
    } else if (provider === 'deepseek') {
      const client = new OpenAI({ apiKey, baseURL: DEEPSEEK_BASE_URL });
      await client.chat.completions.create({
        model: localSettings.getProviderModel('deepseek') || DEFAULT_DEEPSEEK_MODEL,
        max_tokens: 1,
        messages: [{ role: 'user', content: 'hi' }],
      });
    } else if (provider === 'ollama') {
      const client = new OpenAI({ apiKey: 'ollama', baseURL: localSettings.getOllamaBaseUrl() });
      await client.chat.completions.create({
        model: localSettings.getProviderModel('ollama') || DEFAULT_OLLAMA_MODEL,
        max_tokens: 1,
        messages: [{ role: 'user', content: 'hi' }],
      });
    } else {
      throw new Error(`Unknown provider: ${provider}`);
    }
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_SAVE_KEY, async (event, provider, apiKey) => {
    if (typeof apiKey !== 'string' || !apiKey.trim()) {
      throw new Error('API key must be a non-empty string.');
    }
    secureStore.saveApiKey(provider, apiKey.trim());
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_CLEAR_KEY, async (event, provider) => {
    secureStore.clearApiKey(provider);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.SETTINGS_HAS_KEY, async (event, provider) => {
    return secureStore.hasApiKey(provider);
  });

  ipcMain.handle(CHANNELS.SEMGREP_CHECK, async () => {
    return semgrepRunner.checkInstalled();
  });

  ipcMain.handle(CHANNELS.GITLEAKS_CHECK, async () => {
    return gitleaksRunner.checkInstalled();
  });

  ipcMain.handle(CHANNELS.NPM_AUDIT_CHECK, async () => {
    return npmAuditRunner.checkInstalled();
  });
}

module.exports = { registerSettingsHandlers };
