// Shared IPC channel names and data-shape documentation for main/preload/renderer.

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

// Finding shape (see MrRobotBot.md / plan for full rationale):
// {
//   id: string,
//   source: 'semgrep' | 'gitleaks' | 'npm-audit' | 'claude' | 'both',
//   severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
//   title: string,
//   description: string,
//   file: string,
//   line: number,
//   lineEnd?: number,
//   ruleId?: string,
//   cwe?: string[],
//   owasp?: string[],
//   confidence?: 'high' | 'medium' | 'low',
//   mergedFrom?: string[],
//   verified?: boolean,        // true if an AI finding survived the verifier pass
//   verifierReason?: string,   // verifier's one-line rationale for confirming it
// }

module.exports = { CHANNELS };
