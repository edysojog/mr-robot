const FolderSelectScreen = (() => {
  let selectedFolder = null;

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Splits a full path into its last segment (shown bold, as the card's
  // "name") and everything before it (shown small/muted underneath) --
  // reads better than one long absolute path crammed onto a single line.
  function splitPath(folderPath) {
    const normalized = folderPath.replace(/\\/g, '/').replace(/\/+$/, '');
    const idx = normalized.lastIndexOf('/');
    if (idx === -1) return { name: normalized, parent: '' };
    return { name: normalized.slice(idx + 1), parent: normalized.slice(0, idx) };
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function getSelectedTools() {
    return {
      semgrep: document.getElementById('tool-semgrep-checkbox').checked,
      gitleaks: document.getElementById('tool-gitleaks-checkbox').checked,
      npmAudit: document.getElementById('tool-npmaudit-checkbox').checked,
      osv: document.getElementById('tool-osv-checkbox').checked,
      ai: document.getElementById('tool-ai-checkbox').checked,
    };
  }

  function updateStartButton() {
    const startBtn = document.getElementById('start-scan-btn');
    const tools = getSelectedTools();
    const anySelected = tools.semgrep || tools.gitleaks || tools.npmAudit || tools.osv || tools.ai;
    const semgrepOk = !tools.semgrep || FolderSelectScreen.semgrepOk;
    const gitleaksOk = !tools.gitleaks || FolderSelectScreen.gitleaksOk;
    const npmAuditOk = !tools.npmAudit || FolderSelectScreen.npmAuditOk;
    const osvOk = !tools.osv || FolderSelectScreen.hasDependencyManifest;
    const aiOk = !tools.ai || FolderSelectScreen.keyReady;
    startBtn.disabled = !(selectedFolder && anySelected && semgrepOk && gitleaksOk && npmAuditOk && osvOk && aiOk);
  }

  function applyFolderResult(result) {
    if (!result) return;

    selectedFolder = result.rootDir;
    document.getElementById('folder-path').textContent = result.rootDir;
    document.getElementById('folder-path').classList.remove('muted');

    const summary = document.getElementById('folder-summary');
    summary.style.display = 'block';
    document.getElementById('file-count').textContent = result.fileCount;
    document.getElementById('total-size').textContent = formatBytes(result.totalBytes);
    document.getElementById('truncated-row').style.display = result.truncated ? 'flex' : 'none';

    const diffCheckbox = document.getElementById('diff-mode-checkbox');
    const diffText = document.getElementById('diff-mode-text');
    diffCheckbox.disabled = !result.isGitRepo;
    if (!result.isGitRepo) {
      diffCheckbox.checked = false;
      diffText.textContent = 'diff mode unavailable — not a git repository';
    } else {
      diffText.textContent = `diff mode: scan only files changed since last commit (${result.changedFileCount} changed)`;
    }

    document.getElementById('hook-row').style.display = result.isGitRepo ? 'flex' : 'none';
    if (result.isGitRepo) refreshHookStatus();

    const npmAuditCheckbox = document.getElementById('tool-npmaudit-checkbox');
    const npmAuditStatus = document.getElementById('npmaudit-status');
    FolderSelectScreen.hasPackageJson = result.hasPackageJson;
    if (!result.hasPackageJson) {
      npmAuditCheckbox.checked = false;
      npmAuditCheckbox.disabled = true;
      npmAuditStatus.textContent = 'npm audit unavailable — no package.json in this folder';
    } else if (FolderSelectScreen.npmAuditOk) {
      npmAuditCheckbox.disabled = false;
      npmAuditStatus.textContent = 'npm audit ready (package.json found)';
    }

    const osvCheckbox = document.getElementById('tool-osv-checkbox');
    const osvDot = document.getElementById('osv-dot');
    const osvStatus = document.getElementById('osv-status');
    FolderSelectScreen.hasDependencyManifest = result.hasDependencyManifest;
    if (!result.hasDependencyManifest) {
      osvCheckbox.checked = false;
      osvCheckbox.disabled = true;
      osvDot.className = 'status-dot bad';
      osvStatus.textContent = 'OSV dependency scan unavailable — no requirements.txt/go.mod/Cargo.lock in this folder';
    } else {
      osvCheckbox.disabled = false;
      osvDot.className = 'status-dot ok';
      osvStatus.textContent = 'OSV dependency scan ready (no install needed, uses the public OSV.dev API)';
    }

    updateStartButton();
  }

  async function refreshHookStatus() {
    const statusText = document.getElementById('hook-status-text');
    const installBtn = document.getElementById('hook-install-btn');
    const uninstallBtn = document.getElementById('hook-uninstall-btn');

    const status = await IpcClient.getHookStatus(selectedFolder);
    if (status === 'installed') {
      statusText.textContent = 'pre-commit hook: installed (blocks commits with new high/critical findings)';
      installBtn.style.display = 'none';
      uninstallBtn.style.display = 'inline-block';
    } else if (status === 'foreign') {
      statusText.textContent = 'pre-commit hook: an existing hook was found — not managed by MrRobotBot';
      installBtn.style.display = 'none';
      uninstallBtn.style.display = 'none';
    } else {
      statusText.textContent = 'pre-commit hook: not installed';
      installBtn.style.display = 'inline-block';
      uninstallBtn.style.display = 'none';
    }
  }

  function renderRecentFolders(recentFolders) {
    const panel = document.getElementById('recent-folders-panel');
    const list = document.getElementById('recent-folders-list');
    list.innerHTML = '';

    if (!recentFolders || recentFolders.length === 0) {
      panel.style.display = 'none';
      return;
    }
    panel.style.display = 'block';

    recentFolders.forEach((folderPath) => {
      const { name, parent } = splitPath(folderPath);
      const row = document.createElement('div');
      row.className = 'recent-folder-card';
      row.title = folderPath;
      row.innerHTML = `
        <span class="recent-folder-icon">[dir]</span>
        <span class="recent-folder-text">
          <span class="recent-folder-name">${escapeHtml(name)}</span>
          ${parent ? `<span class="recent-folder-parent muted">${escapeHtml(parent)}</span>` : ''}
        </span>
      `;
      row.addEventListener('click', async () => {
        const result = await IpcClient.selectRecentFolder(folderPath);
        if (!result) {
          // Folder no longer exists on disk -- refresh to drop it from the list.
          refreshStatus();
          return;
        }
        applyFolderResult(result);
      });
      list.appendChild(row);
    });
  }

  async function refreshStatus() {
    const semgrepDot = document.getElementById('semgrep-dot');
    const semgrepStatus = document.getElementById('semgrep-status');
    const semgrepCheckbox = document.getElementById('tool-semgrep-checkbox');
    const gitleaksDot = document.getElementById('gitleaks-dot');
    const gitleaksStatus = document.getElementById('gitleaks-status');
    const gitleaksCheckbox = document.getElementById('tool-gitleaks-checkbox');
    const npmAuditDot = document.getElementById('npmaudit-dot');
    const npmAuditStatus = document.getElementById('npmaudit-status');
    const npmAuditCheckbox = document.getElementById('tool-npmaudit-checkbox');
    const apikeyDot = document.getElementById('apikey-dot');
    const apikeyStatus = document.getElementById('apikey-status');

    const [semgrep, gitleaks, npmAudit, settings] = await Promise.all([
      IpcClient.checkSemgrep(),
      IpcClient.checkGitleaks(),
      IpcClient.checkNpmAudit(),
      IpcClient.getSettings(),
    ]);

    FolderSelectScreen.semgrepOk = semgrep.installed;
    semgrepDot.className = 'status-dot ' + (semgrep.installed ? 'ok' : 'bad');
    semgrepStatus.textContent = semgrep.installed
      ? `semgrep detected (${semgrep.version})`
      : 'semgrep not found — install with "pip install semgrep"';
    semgrepCheckbox.disabled = !semgrep.installed;
    if (!semgrep.installed) semgrepCheckbox.checked = false;

    FolderSelectScreen.gitleaksOk = gitleaks.installed;
    gitleaksDot.className = 'status-dot ' + (gitleaks.installed ? 'ok' : 'bad');
    gitleaksStatus.textContent = gitleaks.installed
      ? `gitleaks detected (${gitleaks.version})`
      : 'gitleaks not found — install from github.com/gitleaks/gitleaks';
    gitleaksCheckbox.disabled = !gitleaks.installed;
    if (!gitleaks.installed) gitleaksCheckbox.checked = false;

    FolderSelectScreen.npmAuditOk = npmAudit.installed;
    npmAuditDot.className = 'status-dot ' + (npmAudit.installed ? 'ok' : 'bad');
    npmAuditStatus.textContent = npmAudit.installed
      ? `npm detected (${npmAudit.version}) — select a folder with package.json to enable`
      : 'npm not found on PATH';
    npmAuditCheckbox.disabled = !npmAudit.installed || !FolderSelectScreen.hasPackageJson;
    if (!npmAudit.installed) npmAuditCheckbox.checked = false;

    // No local tool for OSV -- it's a keyless public API call, so unlike
    // the checks above there's nothing to detect on PATH. Applicability is
    // purely per-folder (does a requirements.txt/go.mod/Cargo.lock exist),
    // which applyFolderResult() resolves once a folder is actually picked.
    const osvDot = document.getElementById('osv-dot');
    const osvStatus = document.getElementById('osv-status');
    const osvCheckbox = document.getElementById('tool-osv-checkbox');
    if (!FolderSelectScreen.hasDependencyManifest) {
      osvDot.className = 'status-dot pending';
      osvStatus.textContent = 'OSV dependency scan — pick a folder to check applicability';
      osvCheckbox.disabled = true;
      osvCheckbox.checked = false;
    }

    const provider = settings.provider;
    const hasKeys = settings.hasKeys || {};
    // Maps the provider dropdown's value to the secureStore key it's saved
    // under (a pre-existing mismatch: Claude's key is stored as "anthropic"
    // for backward compat) and the label shown in the status line.
    const PROVIDER_KEY_INFO = {
      groq: { storeKey: 'groq', label: 'Groq' },
      claude: { storeKey: 'anthropic', label: 'Anthropic' },
      gemini: { storeKey: 'gemini', label: 'Gemini' },
      openai: { storeKey: 'openai', label: 'OpenAI' },
    };

    let keyReady;
    if (provider === 'mock') {
      keyReady = true;
      apikeyStatus.textContent = 'mock mode enabled — LLM pass uses canned findings, no key needed';
    } else if (provider === 'ollama') {
      keyReady = true;
      apikeyStatus.textContent = 'ollama mode — local, no key needed (use "Test Connection" in Settings to verify it\'s running)';
    } else {
      const info = PROVIDER_KEY_INFO[provider];
      keyReady = !!hasKeys[info.storeKey];
      apikeyStatus.textContent = keyReady
        ? `${info.label} API key set`
        : `no ${info.label} API key set — open settings to add one`;
    }
    FolderSelectScreen.keyReady = keyReady;
    apikeyDot.className = 'status-dot ' + (keyReady ? 'ok' : 'bad');

    renderRecentFolders(settings.recentFolders);
    updateStartButton();
  }

  function init() {
    document.getElementById('pick-folder-btn').addEventListener('click', async () => {
      const result = await IpcClient.pickFolder();
      if (!result) return;
      applyFolderResult(result);
      refreshStatus(); // repopulate the recent-folders list with this pick at the top
    });

    ['tool-semgrep-checkbox', 'tool-gitleaks-checkbox', 'tool-npmaudit-checkbox', 'tool-ai-checkbox'].forEach((id) => {
      document.getElementById(id).addEventListener('change', updateStartButton);
    });

    document.getElementById('start-scan-btn').addEventListener('click', (event) => {
      if (!selectedFolder) return;
      // Disable immediately so a fast double-click can't fire two concurrent scans.
      event.currentTarget.disabled = true;
      const diffMode = document.getElementById('diff-mode-checkbox').checked;
      const tools = getSelectedTools();
      ScanProgressScreen.start(selectedFolder, diffMode, tools);
    });

    document.getElementById('hook-install-btn').addEventListener('click', async () => {
      try {
        await IpcClient.installHook(selectedFolder);
      } catch (err) {
        alert('could not install hook: ' + err.message);
      }
      refreshHookStatus();
    });

    document.getElementById('hook-uninstall-btn').addEventListener('click', async () => {
      try {
        await IpcClient.uninstallHook(selectedFolder);
      } catch (err) {
        alert('could not uninstall hook: ' + err.message);
      }
      refreshHookStatus();
    });

    refreshStatus();
    Typewriter.play('#screen-folder');
  }

  return {
    init,
    refreshStatus,
    semgrepOk: false,
    gitleaksOk: false,
    npmAuditOk: false,
    hasPackageJson: false,
    hasDependencyManifest: false,
    keyReady: false,
  };
})();
