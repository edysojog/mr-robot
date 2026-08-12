const { ipcMain } = require('electron');
const { CHANNELS } = require('../../shared/types');
const secureStore = require('../services/secureStore');
const localSettings = require('../services/localSettings');
const pocVerifier = require('../services/pocVerifier');

function secureStoreKeyFor(provider) {
  return provider === 'claude' ? 'anthropic' : provider;
}

function registerPocHandlers() {
  ipcMain.handle(CHANNELS.POC_CHECK_DOCKER, async () => {
    return pocVerifier.checkDockerInstalled();
  });

  ipcMain.handle(CHANNELS.POC_VERIFY, async (event, rootDir, finding) => {
    if (!localSettings.getPocVerificationEnabled()) {
      throw new Error('Sandboxed PoC verification is disabled. Enable it in Settings first.');
    }

    const provider = localSettings.getProvider();
    if (!localSettings.KEYLESS_PROVIDERS.includes(provider) && !secureStore.hasApiKey(secureStoreKeyFor(provider))) {
      throw new Error(`No ${provider} API key set. Add one in Settings before requesting a PoC.`);
    }
    const apiKey = localSettings.KEYLESS_PROVIDERS.includes(provider) ? null : secureStore.getApiKey(secureStoreKeyFor(provider));

    const LOG_PATH = 'C:\\Users\\EDUARD~1.DUM\\AppData\\Local\\Temp\\claude\\C--Users-eduardionut-dumitrac-Desktop-mr-robot\\45f9eda8-ddcd-49eb-8295-dcb8e795c5ae\\scratchpad\\poc-verify-log.jsonl';
    const logEntry = (obj) => require('fs').appendFileSync(LOG_PATH, JSON.stringify(obj) + '\n', 'utf8');

    try {
      const result = await pocVerifier.verifyFinding({
        provider,
        apiKey,
        model: localSettings.getProviderModel(provider),
        ollamaBaseUrl: localSettings.getOllamaBaseUrl(),
        rootDir,
        finding,
      });
      logEntry({
        time: new Date().toISOString(),
        findingTitle: finding.title,
        findingFile: finding.file,
        vulnClass: result.vulnClass,
        verdict: result.verdict,
        retried: result.retried,
        exitCode: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        harness: result.harness,
      });
      return result;
    } catch (err) {
      logEntry({
        time: new Date().toISOString(),
        findingTitle: finding.title,
        findingFile: finding.file,
        error: err.message,
      });
      throw err;
    }
  });
}

module.exports = { registerPocHandlers };
