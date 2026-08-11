const path = require('path');
const crypto = require('crypto');
const { ipcMain, BrowserWindow } = require('electron');
const { CHANNELS } = require('../../shared/types');
const semgrepRunner = require('../services/semgrepRunner');
const gitleaksRunner = require('../services/gitleaksRunner');
const npmAuditRunner = require('../services/npmAuditRunner');
const osvRunner = require('../services/osvRunner');
const fileWalker = require('../services/fileWalker');
const findingsMerger = require('../services/findingsMerger');
const baselineStore = require('../services/baselineStore');
const scanHistoryStore = require('../services/scanHistoryStore');
const gitDiff = require('../services/gitDiff');
const secureStore = require('../services/secureStore');
const localSettings = require('../services/localSettings');
const { AnthropicAuditor } = require('../services/claudeAuditor');
const { GroqAuditor } = require('../services/groqAuditor');
const { GeminiAuditor } = require('../services/geminiAuditor');
const { OpenAIAuditor } = require('../services/openaiAuditor');
const { OllamaAuditor } = require('../services/ollamaAuditor');
const { MockAuditor } = require('../services/mockAuditor');

function buildAuditor(provider) {
  const verify = localSettings.getVerificationEnabled();
  const recon = localSettings.getReconEnabled();
  const model = localSettings.getProviderModel(provider);

  if (provider === 'mock') return new MockAuditor(verify, recon);
  if (provider === 'groq') return new GroqAuditor(secureStore.getApiKey('groq'), model, verify, recon);
  if (provider === 'gemini') return new GeminiAuditor(secureStore.getApiKey('gemini'), model, verify, recon);
  if (provider === 'openai') return new OpenAIAuditor(secureStore.getApiKey('openai'), model, verify, recon);
  if (provider === 'ollama') return new OllamaAuditor(localSettings.getOllamaBaseUrl(), model, verify, recon);
  return new AnthropicAuditor(secureStore.getApiKey('anthropic'), model, verify, recon);
}

// Tracks in-flight scans so scan:cancel has something to act on.
const activeScans = new Map();

function registerScanHandlers() {
  ipcMain.handle(CHANNELS.SCAN_START, async (event, folderPath, diffMode, tools) => {
    const scanId = crypto.randomUUID();
    const enabled = { semgrep: true, gitleaks: true, npmAudit: true, osv: true, ai: true, ...tools };
    const win = BrowserWindow.fromWebContents(event.sender);

    const send = (channel, payload) => {
      console.log(`[scan ${scanId}] ${channel}`, payload.message || `${payload.findings ? payload.findings.length + ' findings' : ''}`);
      if (!win.isDestroyed()) win.webContents.send(channel, { scanId, ...payload });
    };

    activeScans.set(scanId, { cancelled: false });
    const isCancelled = () => !!(activeScans.get(scanId) && activeScans.get(scanId).cancelled);

    (async () => {
      try {
        let changedRelPaths = null;
        if (diffMode) {
          send(CHANNELS.SCAN_PROGRESS, { message: 'checking git for changed files…' });
          changedRelPaths = await gitDiff.getChangedFiles(folderPath);

          if (changedRelPaths.length === 0) {
            send(CHANNELS.SCAN_COMPLETE, {
              findings: [],
              summary: {
                folderPath,
                skippedCount: 0,
                findingCount: 0,
                suppressedCount: 0,
                diffMode: true,
                changedFileCount: 0,
                claudePartial: false,
                completedAt: new Date().toISOString(),
              },
            });
            return;
          }
          send(CHANNELS.SCAN_PROGRESS, { message: `${changedRelPaths.length} changed file(s) found` });
        }

        send(CHANNELS.SCAN_PROGRESS, { message: diffMode ? 'scanning changed files' : `scanning ${folderPath}` });

        const semgrepTargets = changedRelPaths
          ? changedRelPaths.map((rel) => path.join(folderPath, rel))
          : undefined;

        const progress = (message) => send(CHANNELS.SCAN_PROGRESS, { message });

        let semgrepFindings = [];
        let skippedCount = 0;
        if (enabled.semgrep) {
          const result = await semgrepRunner.runScan(folderPath, progress, semgrepTargets);
          semgrepFindings = result.findings;
          skippedCount = result.skippedCount;
        } else {
          progress('semgrep pass skipped (unchecked)');
        }

        if (isCancelled()) return;

        let gitleaksFindings = [];
        if (enabled.gitleaks) {
          const result = await gitleaksRunner.runScan(folderPath, progress);
          gitleaksFindings = result.findings;
        } else {
          progress('gitleaks pass skipped (unchecked)');
        }

        if (isCancelled()) return;

        let npmAuditFindings = [];
        if (enabled.npmAudit) {
          const result = await npmAuditRunner.runScan(folderPath, progress);
          npmAuditFindings = result.findings;
        } else {
          progress('npm audit pass skipped (unchecked)');
        }

        if (isCancelled()) return;

        let osvFindings = [];
        if (enabled.osv) {
          const result = await osvRunner.runScan(folderPath, progress);
          osvFindings = result.findings;
        } else {
          progress('OSV dependency scan skipped (unchecked)');
        }

        if (isCancelled()) return;

        const staticFindings = [...semgrepFindings, ...gitleaksFindings, ...npmAuditFindings, ...osvFindings];

        let claudeFindings = [];
        let claudePartial = false;
        if (enabled.ai) {
          const provider = localSettings.getProvider();
          if (!localSettings.KEYLESS_PROVIDERS.includes(provider) && !secureStore.hasApiKey(provider)) {
            throw new Error(`No ${provider} API key set. Add one in Settings, or switch to mock mode, before scanning.`);
          }

          progress(`preparing files for the ${provider} pass…`);
          const auditFiles = changedRelPaths
            ? await fileWalker.filesFromList(folderPath, changedRelPaths)
            : (await fileWalker.walk(folderPath)).files;

          const auditor = buildAuditor(provider);
          const result = await auditor.review(auditFiles, staticFindings, progress);
          claudeFindings = result.findings;
          claudePartial = result.partial;
        } else {
          progress('AI pass skipped (unchecked)');
        }

        if (isCancelled()) return;

        const merged = findingsMerger.merge(staticFindings, claudeFindings);
        const { kept, suppressedCount } = baselineStore.filterSuppressed(folderPath, merged);

        const previousScan = scanHistoryStore.getHistory(folderPath)[0] || null;
        const summary = {
          folderPath,
          skippedCount,
          findingCount: kept.length,
          suppressedCount,
          diffMode: !!diffMode,
          changedFileCount: changedRelPaths ? changedRelPaths.length : undefined,
          claudePartial,
          completedAt: new Date().toISOString(),
        };
        scanHistoryStore.recordScan(folderPath, kept, summary);
        summary.previousScan = previousScan;

        send(CHANNELS.SCAN_COMPLETE, { findings: kept, summary });
      } catch (err) {
        send(CHANNELS.SCAN_ERROR, { message: err.message });
      } finally {
        activeScans.delete(scanId);
      }
    })();

    return { scanId };
  });

  ipcMain.handle(CHANNELS.SCAN_CANCEL, async (event, scanId) => {
    const scan = activeScans.get(scanId);
    if (scan) scan.cancelled = true;
    return { ok: true };
  });
}

module.exports = { registerScanHandlers };
