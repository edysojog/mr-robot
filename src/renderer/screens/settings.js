const SettingsScreen = (() => {
  const PROVIDERS = ['groq', 'claude', 'gemini', 'openai', 'ollama'];
  const STEP_COUNT = 5; // intro, choose provider, configure provider, passes, tools
  let onboarding = false;
  let currentStep = 0;

  async function refreshToolStatus() {
    const semgrepDot = document.getElementById('settings-semgrep-dot');
    const semgrepStatus = document.getElementById('settings-semgrep-status');
    const gitleaksDot = document.getElementById('settings-gitleaks-dot');
    const gitleaksStatus = document.getElementById('settings-gitleaks-status');
    const npmAuditDot = document.getElementById('settings-npmaudit-dot');
    const npmAuditStatus = document.getElementById('settings-npmaudit-status');

    semgrepStatus.textContent = 'checking Semgrep…';
    gitleaksStatus.textContent = 'checking Gitleaks…';
    npmAuditStatus.textContent = 'checking npm…';
    [semgrepDot, gitleaksDot, npmAuditDot].forEach((d) => { d.className = 'status-dot pending'; });

    const [semgrep, gitleaks, npmAudit] = await Promise.all([
      IpcClient.checkSemgrep(),
      IpcClient.checkGitleaks(),
      IpcClient.checkNpmAudit(),
    ]);

    semgrepDot.className = 'status-dot ' + (semgrep.installed ? 'ok' : 'bad');
    semgrepStatus.textContent = semgrep.installed
      ? `semgrep detected (${semgrep.version})`
      : 'semgrep not found — install with "pip install semgrep"';

    gitleaksDot.className = 'status-dot ' + (gitleaks.installed ? 'ok' : 'bad');
    gitleaksStatus.textContent = gitleaks.installed
      ? `gitleaks detected (${gitleaks.version})`
      : 'gitleaks not found — install from github.com/gitleaks/gitleaks (optional)';

    npmAuditDot.className = 'status-dot ' + (npmAudit.installed ? 'ok' : 'bad');
    npmAuditStatus.textContent = npmAudit.installed
      ? `npm detected (${npmAudit.version})`
      : 'npm not found on PATH (optional)';
  }

  const TOOL_LABELS = { semgrep: 'Semgrep', gitleaks: 'Gitleaks', npm: 'npm / Node.js' };

  async function installMissingTools() {
    const btn = document.getElementById('install-tools-btn');
    const logEl = document.getElementById('install-tools-log');
    logEl.style.display = 'block';
    logEl.textContent = 'checking what\'s missing…\n';
    btn.disabled = true;

    const [semgrep, gitleaks, npmAudit] = await Promise.all([
      IpcClient.checkSemgrep(),
      IpcClient.checkGitleaks(),
      IpcClient.checkNpmAudit(),
    ]);
    const missing = [];
    if (!semgrep.installed) missing.push('semgrep');
    if (!gitleaks.installed) missing.push('gitleaks');
    if (!npmAudit.installed) missing.push('npm');

    if (missing.length === 0) {
      logEl.textContent += 'everything is already installed.\n';
      btn.disabled = false;
      return;
    }

    for (const tool of missing) {
      const label = TOOL_LABELS[tool];
      logEl.textContent += `installing ${label}…\n`;
      logEl.scrollTop = logEl.scrollHeight;
      try {
        const result = await IpcClient.installTool(tool);
        logEl.textContent += result.success
          ? `${label}: installed via ${result.method}\n`
          : `${label}: no package manager on this machine could install it (tried ${result.attempts.map((a) => a.label).join(', ')}) — install manually\n`;
      } catch (err) {
        logEl.textContent += `${label}: error — ${err.message}\n`;
      }
      logEl.scrollTop = logEl.scrollHeight;
    }

    btn.disabled = false;
    await refreshToolStatus();
  }

  function selectProviderCard(provider) {
    document.querySelectorAll('.provider-card').forEach((card) => {
      card.classList.toggle('active', card.dataset.provider === provider);
    });
    PROVIDERS.forEach((p) => {
      document.getElementById(`provider-config-${p}`).style.display = p === provider ? 'block' : 'none';
    });
  }

  async function refreshProviderSettings() {
    const settings = await IpcClient.getSettings();
    selectProviderCard(settings.provider);
    document.getElementById('verification-checkbox').checked = settings.verificationEnabled;
    document.getElementById('recon-checkbox').checked = settings.reconEnabled;

    const models = settings.providerModels || {};
    document.getElementById('claude-model-select').value = models.claude || 'claude-sonnet-5';
    document.getElementById('groq-model-input').value = models.groq || '';
    document.getElementById('gemini-model-input').value = models.gemini || '';
    document.getElementById('openai-model-input').value = models.openai || '';
    document.getElementById('ollama-model-input').value = models.ollama || '';
    document.getElementById('ollama-baseurl-input').value = settings.ollamaBaseUrl || '';
  }

  // Save/Clear/Test buttons for a stored-API-key provider (anthropic, groq,
  // gemini, openai). Ollama has no key -- wired separately below.
  function wireKeySection(provider, ids) {
    document.getElementById(ids.save).addEventListener('click', async () => {
      const input = document.getElementById(ids.input);
      const statusEl = document.getElementById(ids.status);
      if (!input.value.trim()) {
        statusEl.textContent = 'enter a key first';
        statusEl.className = 'warn';
        return;
      }
      try {
        await IpcClient.saveApiKey(provider, input.value.trim());
        input.value = '';
        statusEl.textContent = 'saved';
        statusEl.className = 'ok';
      } catch (err) {
        statusEl.textContent = 'failed: ' + err.message;
        statusEl.className = 'danger';
      }
    });

    document.getElementById(ids.clear).addEventListener('click', async () => {
      await IpcClient.clearApiKey(provider);
      const statusEl = document.getElementById(ids.status);
      statusEl.textContent = 'cleared';
      statusEl.className = 'muted';
    });

    document.getElementById(ids.test).addEventListener('click', async () => {
      const statusEl = document.getElementById(ids.status);
      const costNote = provider === 'anthropic' || provider === 'openai' || provider === 'gemini' ? ' (real, tiny paid request)' : ' (free tier)';
      statusEl.textContent = 'testing…' + costNote;
      statusEl.className = 'muted';
      try {
        await IpcClient.testKey(provider);
        statusEl.textContent = 'key works';
        statusEl.className = 'ok';
      } catch (err) {
        statusEl.textContent = 'test failed: ' + err.message;
        statusEl.className = 'danger';
      }
    });
  }

  // A per-provider model override input/select -- saves on change, empty
  // input clears the override back to that auditor's own default.
  function wireModelInput(provider, inputId) {
    document.getElementById(inputId).addEventListener('change', async (event) => {
      await IpcClient.setModel(provider, event.target.value);
    });
  }

  function wireOllama() {
    document.getElementById('ollama-baseurl-input').addEventListener('change', async (event) => {
      await IpcClient.setOllamaUrl(event.target.value);
    });

    document.getElementById('ollama-test-btn').addEventListener('click', async () => {
      const statusEl = document.getElementById('ollama-status');
      statusEl.textContent = 'testing connection…';
      statusEl.className = 'muted';
      try {
        await IpcClient.testKey('ollama');
        statusEl.textContent = 'connected';
        statusEl.className = 'ok';
      } catch (err) {
        statusEl.textContent = 'failed: ' + err.message;
        statusEl.className = 'danger';
      }
    });
  }

  // Onboarding renders as a 5-slide carousel (intro / provider / configure /
  // passes / tools) with dot indicators and < > nav. Regular settings (opened
  // later via the "settings" button) ignores steps entirely -- everything
  // shows on one page, same as before.
  function renderDots() {
    const dotsEl = document.getElementById('carousel-dots');
    dotsEl.innerHTML = '';
    for (let i = 0; i < STEP_COUNT; i++) {
      const dot = document.createElement('span');
      dot.className = 'carousel-dot' + (i === currentStep ? ' active' : '');
      dot.addEventListener('click', () => { currentStep = i; applyStep(); });
      dotsEl.appendChild(dot);
    }
  }

  function updateBackButton() {
    const btn = document.getElementById('back-btn');
    if (onboarding) {
      btn.textContent = "Let's go →";
      btn.style.display = currentStep === STEP_COUNT - 1 ? '' : 'none';
    } else {
      btn.textContent = '← Back';
      btn.style.display = '';
    }
  }

  function applyStep() {
    document.getElementById('screen-settings').classList.toggle('onboarding-mode', onboarding);
    document.querySelectorAll('[data-onboard-step]').forEach((el) => {
      const step = Number(el.dataset.onboardStep);
      // step 0 (the welcome blurb) only ever shows during onboarding's first
      // slide -- everything else shows fully outside onboarding, like before.
      const visible = step === 0 ? (onboarding && currentStep === 0) : (!onboarding || step === currentStep);
      el.style.display = visible ? '' : 'none';
    });
    document.getElementById('carousel-nav').style.display = onboarding ? 'flex' : 'none';
    document.getElementById('carousel-prev').disabled = currentStep === 0;
    document.getElementById('carousel-next').disabled = currentStep === STEP_COUNT - 1;
    renderDots();
    updateBackButton();
    if (onboarding) Typewriter.play(`[data-onboard-step="${currentStep}"]`);
  }

  // Called on every normal "settings" button click -- not the first-run flow.
  function show() {
    onboarding = false;
    applyStep();
    AppState.show('screen-settings');
    refreshToolStatus();
    refreshProviderSettings();
  }

  // Called once by main.js on launch if setup has never been completed --
  // same screen, but walked through as a carousel starting at the welcome
  // slide, with "Let's go" only reachable on the final step.
  function showOnboarding() {
    onboarding = true;
    currentStep = 0;
    applyStep();
    AppState.show('screen-settings');
    refreshToolStatus();
    refreshProviderSettings();
  }

  function init() {
    document.getElementById('settings-btn').addEventListener('click', show);

    document.getElementById('back-btn').addEventListener('click', async () => {
      await IpcClient.setSetupComplete(true);
      AppState.show('screen-folder');
      FolderSelectScreen.refreshStatus();
    });

    document.getElementById('recheck-semgrep-btn').addEventListener('click', refreshToolStatus);
    document.getElementById('install-tools-btn').addEventListener('click', installMissingTools);

    document.getElementById('carousel-prev').addEventListener('click', () => {
      if (currentStep > 0) { currentStep--; applyStep(); }
    });
    document.getElementById('carousel-next').addEventListener('click', () => {
      if (currentStep < STEP_COUNT - 1) { currentStep++; applyStep(); }
    });

    document.querySelectorAll('.provider-card').forEach((card) => {
      card.addEventListener('click', async () => {
        const provider = card.dataset.provider;
        selectProviderCard(provider);
        await IpcClient.setProvider(provider);
        FolderSelectScreen.refreshStatus();
        if (onboarding && currentStep === 1) { currentStep = 2; applyStep(); }
      });
    });

    document.getElementById('verification-checkbox').addEventListener('change', async (event) => {
      await IpcClient.setVerification(event.target.checked);
    });

    document.getElementById('recon-checkbox').addEventListener('change', async (event) => {
      await IpcClient.setRecon(event.target.checked);
    });

    wireKeySection('anthropic', {
      input: 'apikey-input', save: 'save-key-btn', clear: 'clear-key-btn',
      test: 'test-key-btn', status: 'key-save-status',
    });
    wireKeySection('groq', {
      input: 'groq-apikey-input', save: 'groq-save-key-btn', clear: 'groq-clear-key-btn',
      test: 'groq-test-key-btn', status: 'groq-key-status',
    });
    wireKeySection('gemini', {
      input: 'gemini-apikey-input', save: 'gemini-save-key-btn', clear: 'gemini-clear-key-btn',
      test: 'gemini-test-key-btn', status: 'gemini-key-status',
    });
    wireKeySection('openai', {
      input: 'openai-apikey-input', save: 'openai-save-key-btn', clear: 'openai-clear-key-btn',
      test: 'openai-test-key-btn', status: 'openai-key-status',
    });

    wireModelInput('claude', 'claude-model-select');
    wireModelInput('groq', 'groq-model-input');
    wireModelInput('gemini', 'gemini-model-input');
    wireModelInput('openai', 'openai-model-input');
    wireModelInput('ollama', 'ollama-model-input');

    wireOllama();
  }

  return { init, show, showOnboarding };
})();
