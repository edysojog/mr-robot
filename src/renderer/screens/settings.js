const SettingsScreen = (() => {
  const PROVIDERS = ['mock', 'groq', 'claude', 'gemini', 'openai', 'ollama'];
  let onboarding = false;

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
    document.getElementById('specialists-checkbox').checked = settings.specialistsEnabled;

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

  function updateBackButton() {
    document.getElementById('back-btn').textContent = onboarding ? 'Continue →' : '← Back';
  }

  // Called on every normal "settings" button click -- not the first-run flow.
  function show() {
    onboarding = false;
    document.getElementById('settings-intro').style.display = 'none';
    updateBackButton();
    AppState.show('screen-settings');
    refreshToolStatus();
    refreshProviderSettings();
  }

  // Called once by main.js on launch if setup has never been completed --
  // same screen, but with the welcome blurb shown and the back button
  // reframed as moving forward rather than returning to a prior screen.
  function showOnboarding() {
    onboarding = true;
    document.getElementById('settings-intro').style.display = 'block';
    updateBackButton();
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

    document.querySelectorAll('.provider-card').forEach((card) => {
      card.addEventListener('click', async () => {
        const provider = card.dataset.provider;
        selectProviderCard(provider);
        await IpcClient.setProvider(provider);
        FolderSelectScreen.refreshStatus();
      });
    });

    document.getElementById('verification-checkbox').addEventListener('change', async (event) => {
      await IpcClient.setVerification(event.target.checked);
    });

    document.getElementById('recon-checkbox').addEventListener('change', async (event) => {
      await IpcClient.setRecon(event.target.checked);
    });

    document.getElementById('specialists-checkbox').addEventListener('change', async (event) => {
      await IpcClient.setSpecialists(event.target.checked);
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
