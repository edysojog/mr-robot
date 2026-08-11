// Thin wrapper around window.mrrobot (exposed by preload.js) so screens
// don't touch the IPC bridge directly.
const IpcClient = {
  pickFolder: () => window.mrrobot.pickFolder(),
  selectRecentFolder: (rootDir) => window.mrrobot.selectRecentFolder(rootDir),
  openFile: (rootDir, relativeFile) => window.mrrobot.openFile(rootDir, relativeFile),
  getSettings: () => window.mrrobot.getSettings(),
  saveApiKey: (provider, key) => window.mrrobot.saveApiKey(provider, key),
  clearApiKey: (provider) => window.mrrobot.clearApiKey(provider),
  hasApiKey: (provider) => window.mrrobot.hasApiKey(provider),
  checkSemgrep: () => window.mrrobot.checkSemgrep(),
  checkGitleaks: () => window.mrrobot.checkGitleaks(),
  checkNpmAudit: () => window.mrrobot.checkNpmAudit(),
  installTool: (tool) => window.mrrobot.installTool(tool),
  setProvider: (provider) => window.mrrobot.setProvider(provider),
  setModel: (provider, model) => window.mrrobot.setModel(provider, model),
  setVerification: (enabled) => window.mrrobot.setVerification(enabled),
  setRecon: (enabled) => window.mrrobot.setRecon(enabled),
  setOllamaUrl: (url) => window.mrrobot.setOllamaUrl(url),
  setSetupComplete: (value) => window.mrrobot.setSetupComplete(value),
  testKey: (provider) => window.mrrobot.testKey(provider),

  startScan: (folderPath, diffMode, tools) => window.mrrobot.startScan(folderPath, diffMode, tools),
  cancelScan: (scanId) => window.mrrobot.cancelScan(scanId),
  onScanProgress: (cb) => window.mrrobot.onScanProgress(cb),
  onScanComplete: (cb) => window.mrrobot.onScanComplete(cb),
  onScanError: (cb) => window.mrrobot.onScanError(cb),

  exportReport: (findings, summary, format) => window.mrrobot.exportReport(findings, summary, format),

  suppressFinding: (rootDir, finding, reason) => window.mrrobot.suppressFinding(rootDir, finding, reason),
  unsuppressFinding: (rootDir, fingerprint) => window.mrrobot.unsuppressFinding(rootDir, fingerprint),
  listSuppressed: (rootDir) => window.mrrobot.listSuppressed(rootDir),

  listScanHistory: (rootDir) => window.mrrobot.listScanHistory(rootDir),

  getHookStatus: (rootDir) => window.mrrobot.getHookStatus(rootDir),
  installHook: (rootDir) => window.mrrobot.installHook(rootDir),
  uninstallHook: (rootDir) => window.mrrobot.uninstallHook(rootDir),

  suggestFix: (rootDir, finding) => window.mrrobot.suggestFix(rootDir, finding),
};
