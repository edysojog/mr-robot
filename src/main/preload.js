const { contextBridge, ipcRenderer } = require('electron');

// Sandboxed preload scripts can only require whitelisted built-ins, not
// arbitrary local files -- so the channel names are inlined here rather
// than imported from ../shared/types.js. Keep these in sync with that file.
const CHANNELS = {
  PICK_FOLDER: 'dialog:pick-folder',
  SELECT_RECENT_FOLDER: 'folder:select-recent',
  SCAN_START: 'scan:start',
  SCAN_CANCEL: 'scan:cancel',
  SCAN_PROGRESS: 'scan:progress',
  SCAN_FINDINGS: 'scan:findings',
  SCAN_COMPLETE: 'scan:complete',
  SCAN_ERROR: 'scan:error',
  SETTINGS_GET: 'settings:get',
  SETTINGS_SAVE_KEY: 'settings:save-key',
  SETTINGS_CLEAR_KEY: 'settings:clear-key',
  SETTINGS_HAS_KEY: 'settings:has-key',
  SETTINGS_SET_PROVIDER: 'settings:set-provider',
  SETTINGS_SET_MODEL: 'settings:set-model',
  SETTINGS_SET_VERIFICATION: 'settings:set-verification',
  SETTINGS_SET_RECON: 'settings:set-recon',
  SETTINGS_SET_OLLAMA_URL: 'settings:set-ollama-url',
  SETTINGS_SET_SETUP_COMPLETE: 'settings:set-setup-complete',
  SETTINGS_TEST_KEY: 'settings:test-key',
  SEMGREP_CHECK: 'semgrep:check-installed',
  GITLEAKS_CHECK: 'gitleaks:check-installed',
  NPM_AUDIT_CHECK: 'npmaudit:check-installed',
  TOOL_INSTALL: 'tools:install',
  REPORT_EXPORT: 'report:export',
  OPEN_FILE: 'file:open',
  BASELINE_SUPPRESS: 'baseline:suppress',
  BASELINE_UNSUPPRESS: 'baseline:unsuppress',
  BASELINE_LIST: 'baseline:list',
  HISTORY_LIST: 'history:list',
  HOOK_STATUS: 'hook:status',
  HOOK_INSTALL: 'hook:install',
  HOOK_UNINSTALL: 'hook:uninstall',
  FIX_SUGGEST: 'fix:suggest',
};

contextBridge.exposeInMainWorld('mrrobot', {
  pickFolder: () => ipcRenderer.invoke(CHANNELS.PICK_FOLDER),
  selectRecentFolder: (rootDir) => ipcRenderer.invoke(CHANNELS.SELECT_RECENT_FOLDER, rootDir),
  openFile: (rootDir, relativeFile) => ipcRenderer.invoke(CHANNELS.OPEN_FILE, rootDir, relativeFile),

  getSettings: () => ipcRenderer.invoke(CHANNELS.SETTINGS_GET),
  saveApiKey: (provider, apiKey) => ipcRenderer.invoke(CHANNELS.SETTINGS_SAVE_KEY, provider, apiKey),
  clearApiKey: (provider) => ipcRenderer.invoke(CHANNELS.SETTINGS_CLEAR_KEY, provider),
  hasApiKey: (provider) => ipcRenderer.invoke(CHANNELS.SETTINGS_HAS_KEY, provider),
  setProvider: (provider) => ipcRenderer.invoke(CHANNELS.SETTINGS_SET_PROVIDER, provider),
  setModel: (provider, model) => ipcRenderer.invoke(CHANNELS.SETTINGS_SET_MODEL, provider, model),
  setVerification: (enabled) => ipcRenderer.invoke(CHANNELS.SETTINGS_SET_VERIFICATION, enabled),
  setRecon: (enabled) => ipcRenderer.invoke(CHANNELS.SETTINGS_SET_RECON, enabled),
  setOllamaUrl: (url) => ipcRenderer.invoke(CHANNELS.SETTINGS_SET_OLLAMA_URL, url),
  setSetupComplete: (value) => ipcRenderer.invoke(CHANNELS.SETTINGS_SET_SETUP_COMPLETE, value),
  testKey: (provider) => ipcRenderer.invoke(CHANNELS.SETTINGS_TEST_KEY, provider),

  checkSemgrep: () => ipcRenderer.invoke(CHANNELS.SEMGREP_CHECK),
  checkGitleaks: () => ipcRenderer.invoke(CHANNELS.GITLEAKS_CHECK),
  checkNpmAudit: () => ipcRenderer.invoke(CHANNELS.NPM_AUDIT_CHECK),
  installTool: (tool) => ipcRenderer.invoke(CHANNELS.TOOL_INSTALL, tool),

  startScan: (folderPath, diffMode, tools) => ipcRenderer.invoke(CHANNELS.SCAN_START, folderPath, diffMode, tools),
  cancelScan: (scanId) => ipcRenderer.invoke(CHANNELS.SCAN_CANCEL, scanId),
  onScanProgress: (callback) => {
    const listener = (event, payload) => callback(payload);
    ipcRenderer.on(CHANNELS.SCAN_PROGRESS, listener);
    return () => ipcRenderer.removeListener(CHANNELS.SCAN_PROGRESS, listener);
  },
  onScanComplete: (callback) => {
    const listener = (event, payload) => callback(payload);
    ipcRenderer.on(CHANNELS.SCAN_COMPLETE, listener);
    return () => ipcRenderer.removeListener(CHANNELS.SCAN_COMPLETE, listener);
  },
  onScanError: (callback) => {
    const listener = (event, payload) => callback(payload);
    ipcRenderer.on(CHANNELS.SCAN_ERROR, listener);
    return () => ipcRenderer.removeListener(CHANNELS.SCAN_ERROR, listener);
  },

  exportReport: (findings, summary, format) =>
    ipcRenderer.invoke(CHANNELS.REPORT_EXPORT, findings, summary, format),

  suppressFinding: (rootDir, finding, reason) =>
    ipcRenderer.invoke(CHANNELS.BASELINE_SUPPRESS, rootDir, finding, reason),
  unsuppressFinding: (rootDir, fingerprint) =>
    ipcRenderer.invoke(CHANNELS.BASELINE_UNSUPPRESS, rootDir, fingerprint),
  listSuppressed: (rootDir) => ipcRenderer.invoke(CHANNELS.BASELINE_LIST, rootDir),

  listScanHistory: (rootDir) => ipcRenderer.invoke(CHANNELS.HISTORY_LIST, rootDir),

  getHookStatus: (rootDir) => ipcRenderer.invoke(CHANNELS.HOOK_STATUS, rootDir),
  installHook: (rootDir) => ipcRenderer.invoke(CHANNELS.HOOK_INSTALL, rootDir),
  uninstallHook: (rootDir) => ipcRenderer.invoke(CHANNELS.HOOK_UNINSTALL, rootDir),

  suggestFix: (rootDir, finding) => ipcRenderer.invoke(CHANNELS.FIX_SUGGEST, rootDir, finding),
});
