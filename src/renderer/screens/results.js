const ResultsScreen = (() => {
  const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  const SOURCES = ['both', 'semgrep', 'gitleaks', 'npm-audit', 'osv', 'claude'];
  const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2, undefined: 3 };

  let allFindings = [];
  let activeSeverities = new Set(SEVERITY_ORDER);
  let activeSources = new Set(SOURCES);
  let currentFolderPath = null;
  let currentSummary = null;
  let groupBy = 'severity';
  let pocVerificationEnabled = false;

  // Class list + matching logic lives in shared/pocClasses.js so it stays in
  // sync with pocVerifier.js (main process), which picks the harness template.
  const isPocEligible = PocClasses.isPocEligible;

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatTrend(findings, previousScan) {
    if (!previousScan) return '';

    const counts = SEVERITY_ORDER.reduce((acc, sev) => ({ ...acc, [sev]: 0 }), {});
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    const totalDelta = findings.length - previousScan.findingCount;
    const severityDeltas = SEVERITY_ORDER
      .map((sev) => ({ sev, delta: counts[sev] - (previousScan.counts[sev] || 0) }))
      .filter((d) => d.delta !== 0)
      .map((d) => `${d.delta > 0 ? '+' : ''}${d.delta} ${d.sev}`);

    const when = new Date(previousScan.timestamp).toLocaleString();
    if (totalDelta === 0 && severityDeltas.length === 0) {
      return `<div class="row"><span class="muted">no change vs last scan (${when})</span></div>`;
    }

    const totalText = `${totalDelta > 0 ? '+' : ''}${totalDelta} total`;
    const cls = totalDelta > 0 ? 'danger' : totalDelta < 0 ? 'ok' : 'muted';
    return `<div class="row"><span class="${cls}">vs last scan (${when}): ${totalText}${severityDeltas.length ? ', ' + severityDeltas.join(', ') : ''}</span></div>`;
  }

  function renderSummary(findings, summary) {
    const counts = SEVERITY_ORDER.reduce((acc, sev) => ({ ...acc, [sev]: 0 }), {});
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    const countsLine = SEVERITY_ORDER
      .map((sev) => `<span class="${sev}">${sev}: ${counts[sev]}</span>`)
      .join('&nbsp;&nbsp;');

    const confirmedCount = findings.filter((f) => f.source === 'both').length;

    document.getElementById('results-summary').innerHTML = `
      <div class="row"><span class="muted">folder:</span> ${summary.folderPath}</div>
      ${summary.diffMode ? `<div class="row"><span class="ok">diff mode: ${summary.changedFileCount} changed file(s) scanned</span></div>` : ''}
      <div class="row"><span class="muted">total findings:</span> ${findings.length}</div>
      <div class="row">${countsLine}</div>
      <div class="row"><span class="ok">confirmed by a static tool + AI: ${confirmedCount}</span></div>
      ${summary.claudePartial ? '<div class="row"><span class="warn">Claude pass hit its batch cap — some files were not analyzed</span></div>' : ''}
      ${formatTrend(findings, summary.previousScan)}
    `;
  }

  function buildFilterPills(containerId, values, activeSet, labelPrefix) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';
    values.forEach((value) => {
      const pill = document.createElement('label');
      pill.className = 'filter-pill' + (activeSet.has(value) ? ' active' : '');
      pill.innerHTML = `<input type="checkbox" ${activeSet.has(value) ? 'checked' : ''} /> ${labelPrefix}${value}`;
      pill.querySelector('input').addEventListener('change', (event) => {
        if (event.target.checked) activeSet.add(value);
        else activeSet.delete(value);
        pill.classList.toggle('active', event.target.checked);
        renderList();
      });
      container.appendChild(pill);
    });
  }

  function applyFilters(findings) {
    const query = document.getElementById('results-search').value.trim().toLowerCase();

    return findings.filter((f) => {
      if (!activeSeverities.has(f.severity)) return false;
      if (!activeSources.has(f.source)) return false;
      if (query) {
        const haystack = `${f.title} ${f.description} ${f.file}`.toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });
  }

  function applySort(findings) {
    const sortBy = document.getElementById('results-sort').value;
    const sorted = [...findings];

    if (sortBy === 'file') {
      sorted.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    } else if (sortBy === 'confidence') {
      sorted.sort((a, b) => CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence]);
    } else {
      sorted.sort((a, b) => {
        const sevDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        if (sevDiff !== 0) return sevDiff;
        const bothA = a.source === 'both' ? 0 : 1;
        const bothB = b.source === 'both' ? 0 : 1;
        if (bothA !== bothB) return bothA - bothB;
        return a.file.localeCompare(b.file);
      });
    }
    return sorted;
  }

  function buildFindingElement(finding) {
    const el = document.createElement('div');
    el.className = `finding ${finding.severity}`;
    el.innerHTML = `
      <div class="finding-head">
        <span><span class="finding-sev ${finding.severity}">${finding.severity}</span> ${escapeHtml(finding.title)}${finding.source === 'both' ? ` <span class="badge ok-badge">confirmed by ${escapeHtml(finding.staticSource || 'static')} + ai</span>` : ''}${finding.verified ? ' <span class="badge ok-badge">verified</span>' : ''}</span>
        <span class="finding-loc">${escapeHtml(finding.file)}:${finding.line}</span>
      </div>
      <div class="finding-detail">
        <div>${escapeHtml(finding.description || '')}</div>
        <div style="margin-top:8px;">
          <span class="badge">source: ${finding.source === 'both' ? `${finding.staticSource || 'static'} + ai` : finding.source}</span>
          ${finding.ruleId ? `<span class="badge">${escapeHtml(finding.ruleId)}</span>` : ''}
          ${finding.confidence ? `<span class="badge">confidence: ${finding.confidence}</span>` : ''}
        </div>
        ${finding.verifierReason ? `<div class="muted" style="margin-top:8px;font-size:12px;">verifier note: ${escapeHtml(finding.verifierReason)}</div>` : ''}
        <button class="open-file-btn" style="margin-top:10px;">open file</button>
        <button class="suggest-fix-btn" style="margin-top:10px;">suggest fix</button>
        ${pocVerificationEnabled && isPocEligible(finding) ? '<button class="verify-poc-btn" style="margin-top:10px;">verify in sandbox (PoC)</button>' : ''}
        <button class="not-a-bug-btn" style="margin-top:10px;">mark as not a bug</button>
        <div class="not-a-bug-form" style="display:none;margin-top:10px;">
          <input class="not-a-bug-reason" type="text" placeholder="reason (optional)" />
          <button class="not-a-bug-confirm" style="margin-top:6px;">confirm suppress</button>
        </div>
        <div class="fix-output" style="display:none;margin-top:10px;"></div>
        <div class="poc-output" style="display:none;margin-top:10px;"></div>
      </div>
    `;
    el.addEventListener('click', () => el.classList.toggle('expanded'));
    el.querySelector('.open-file-btn').addEventListener('click', async (event) => {
      event.stopPropagation();
      try {
        await IpcClient.openFile(currentFolderPath, finding.file);
      } catch (err) {
        alert('could not open file: ' + err.message);
      }
    });
    el.querySelector('.suggest-fix-btn').addEventListener('click', async (event) => {
      event.stopPropagation();
      const btn = event.currentTarget;
      const output = el.querySelector('.fix-output');
      btn.disabled = true;
      btn.textContent = 'asking AI…';
      output.style.display = 'block';
      output.innerHTML = '<div class="log" style="height:auto;max-height:300px;">requesting a fix suggestion — advisory only, nothing is applied automatically…</div>';
      try {
        const result = await IpcClient.suggestFix(currentFolderPath, finding);
        output.innerHTML = `<div class="log" style="height:auto;max-height:300px;">${escapeHtml(result.fix)}</div>`;
      } catch (err) {
        output.innerHTML = `<div class="danger" style="font-size:12px;">failed to get a fix: ${escapeHtml(err.message)}</div>`;
      }
      btn.disabled = false;
      btn.textContent = 'suggest fix';
    });
    const verifyPocBtn = el.querySelector('.verify-poc-btn');
    if (verifyPocBtn) {
      verifyPocBtn.addEventListener('click', async (event) => {
        event.stopPropagation();
        const btn = event.currentTarget;
        const output = el.querySelector('.poc-output');
        btn.disabled = true;
        btn.textContent = 'verifying…';
        output.style.display = 'block';
        output.innerHTML = '<div class="log" style="height:auto;max-height:300px;">writing a test harness and running it in a locked-down Docker container — no network, read-only, capabilities dropped…</div>';
        try {
          const result = await IpcClient.verifyPoc(currentFolderPath, finding);
          const verdictClass = result.verdict === 'VULNERABLE' ? 'danger' : result.verdict === 'NOT_VULNERABLE' ? 'ok' : 'warn';
          const stderrBlock = result.stderr
            ? `<div class="danger" style="font-size:12px;margin-top:6px;">stderr:</div><div class="log" style="height:auto;max-height:200px;">${escapeHtml(result.stderr)}</div>`
            : '';
          const retriedBlock = result.retried
            ? `<div style="font-size:11px;opacity:0.7;margin-bottom:6px;">(harness had a syntax error on the first attempt — regenerated once)</div>`
            : '';
          output.innerHTML = `
            <div class="${verdictClass}" style="font-weight:bold;margin-bottom:6px;">verdict: ${escapeHtml(result.verdict)}</div>
            ${retriedBlock}
            <div class="log" style="height:auto;max-height:300px;">${escapeHtml(result.stdout || '(no output)')}</div>
            ${stderrBlock}
          `;
        } catch (err) {
          output.innerHTML = `<div class="danger" style="font-size:12px;">verification failed: ${escapeHtml(err.message)}</div>`;
        }
        btn.disabled = false;
        btn.textContent = 'verify in sandbox (PoC)';
      });
    }

    el.querySelector('.not-a-bug-btn').addEventListener('click', (event) => {
      event.stopPropagation();
      el.querySelector('.not-a-bug-form').style.display = 'block';
      el.querySelector('.not-a-bug-reason').focus();
    });
    el.querySelector('.not-a-bug-confirm').addEventListener('click', async (event) => {
      event.stopPropagation();
      const reason = el.querySelector('.not-a-bug-reason').value.trim();
      await IpcClient.suppressFinding(currentFolderPath, finding, reason);
      allFindings = allFindings.filter((f) => f.id !== finding.id);
      renderSummary(allFindings, currentSummary);
      renderList();
      refreshSuppressedPanel();
    });
    return el;
  }

  // Findings are bucketed into collapsible sections instead of one flat
  // list -- by severity (CRITICAL/HIGH/MEDIUM/...) by default, or by tool
  // via the group-by selector. Every section starts collapsed; clicking the
  // header reveals its findings.
  function groupKeyFor(finding) {
    return groupBy === 'source' ? finding.source : finding.severity;
  }

  function buildGroupSection(key, items) {
    const section = document.createElement('div');
    section.className = 'finding-group';

    const header = document.createElement('div');
    header.className = 'finding-group-header';
    const labelClass = groupBy === 'severity' ? key : '';
    header.innerHTML = `
      <span class="finding-group-arrow">&#9656;</span>
      <span class="finding-group-label ${labelClass}">${escapeHtml(key)}</span>
      <span class="muted">(${items.length})</span>
    `;

    const body = document.createElement('div');
    body.className = 'finding-group-body';
    body.style.display = 'none';
    items.forEach((finding) => body.appendChild(buildFindingElement(finding)));

    header.addEventListener('click', () => {
      const collapsed = body.style.display === 'none';
      body.style.display = collapsed ? 'block' : 'none';
      header.querySelector('.finding-group-arrow').innerHTML = collapsed ? '&#9662;' : '&#9656;';
    });

    section.appendChild(header);
    section.appendChild(body);
    return section;
  }

  function renderList() {
    const filtered = applySort(applyFilters(allFindings));
    const list = document.getElementById('results-list');
    const countEl = document.getElementById('results-count');
    list.innerHTML = '';

    countEl.textContent = `showing ${filtered.length} of ${allFindings.length} finding(s)`;

    if (filtered.length === 0) {
      list.innerHTML = '<p class="muted">no findings match the current filters.</p>';
      return;
    }

    const groups = new Map();
    filtered.forEach((finding) => {
      const key = groupKeyFor(finding);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(finding);
    });

    const groupOrder = groupBy === 'source' ? SOURCES : SEVERITY_ORDER;
    groupOrder.forEach((key) => {
      const items = groups.get(key);
      if (items && items.length > 0) list.appendChild(buildGroupSection(key, items));
    });
  }

  async function refreshSuppressedPanel() {
    const panel = document.getElementById('suppressed-panel');
    const suppressedSummary = document.getElementById('suppressed-summary');
    const list = document.getElementById('suppressed-list');

    const suppressed = await IpcClient.listSuppressed(currentFolderPath);

    if (suppressed.length === 0) {
      panel.style.display = 'none';
      list.style.display = 'none';
      return;
    }
    panel.style.display = 'block';
    suppressedSummary.textContent = `${suppressed.length} finding(s) marked not-a-bug for this project`;

    list.innerHTML = '';
    suppressed.forEach((s) => {
      const row = document.createElement('div');
      row.className = 'recent-folder-row';
      row.innerHTML = `
        <span class="path">${escapeHtml(s.title)} <span class="muted">— ${escapeHtml(s.file)} (${s.severity})</span>${s.reason ? ` <span class="muted">"${escapeHtml(s.reason)}"</span>` : ''}</span>
        <button class="unsuppress-btn">restore</button>
      `;
      row.querySelector('.unsuppress-btn').addEventListener('click', async () => {
        await IpcClient.unsuppressFinding(currentFolderPath, s.fingerprint);
        refreshSuppressedPanel();
      });
      list.appendChild(row);
    });
  }

  async function refreshHistorySummary() {
    const historySummary = document.getElementById('history-summary');
    const history = await IpcClient.listScanHistory(currentFolderPath);
    historySummary.textContent = history.length === 0
      ? 'no prior scans for this project'
      : `${history.length} prior scan(s) recorded for this project`;
    return history;
  }

  function renderHistoryList(history) {
    const list = document.getElementById('history-list');
    list.innerHTML = '';

    if (history.length === 0) {
      list.innerHTML = '<p class="muted">no scan history yet.</p>';
      return;
    }

    history.forEach((entry) => {
      const when = new Date(entry.timestamp).toLocaleString();
      const countsText = SEVERITY_ORDER.map((sev) => `${entry.counts[sev] || 0} ${sev}`).join(', ');
      const row = document.createElement('div');
      row.className = 'recent-folder-row';
      row.style.cursor = 'default';
      row.innerHTML = `
        <span class="path">${when}${entry.diffMode ? ' <span class="badge">diff</span>' : ''}
          <span class="muted"> — ${entry.findingCount} finding(s) (${countsText})</span>
        </span>
      `;
      list.appendChild(row);
    });
  }

  async function show(findings, summary) {
    allFindings = findings;
    currentFolderPath = summary.folderPath;
    currentSummary = summary;
    activeSeverities = new Set(SEVERITY_ORDER);
    activeSources = new Set(SOURCES);
    groupBy = 'severity';
    document.getElementById('results-search').value = '';
    document.getElementById('results-groupby').value = 'severity';
    document.getElementById('results-sort').value = 'severity';

    const settings = await IpcClient.getSettings();
    pocVerificationEnabled = !!settings.pocVerificationEnabled;

    renderSummary(findings, summary);
    buildFilterPills('results-severity-filters', SEVERITY_ORDER, activeSeverities, '');
    buildFilterPills('results-source-filters', SOURCES, activeSources, 'source: ');
    renderList();
    document.getElementById('suppressed-list').style.display = 'none';
    document.getElementById('history-list').style.display = 'none';
    refreshSuppressedPanel();
    refreshHistorySummary();
    AppState.show('screen-results');
    Typewriter.play('#screen-results');
  }

  function init() {
    document.getElementById('results-back-btn').addEventListener('click', () => {
      AppState.show('screen-folder');
      FolderSelectScreen.refreshStatus();
    });

    document.getElementById('results-search').addEventListener('input', renderList);
    document.getElementById('results-sort').addEventListener('change', renderList);
    document.getElementById('results-groupby').addEventListener('change', (event) => {
      groupBy = event.target.value;
      renderList();
    });

    document.getElementById('manage-suppressed-btn').addEventListener('click', () => {
      const list = document.getElementById('suppressed-list');
      list.style.display = list.style.display === 'none' ? 'block' : 'none';
    });

    document.getElementById('view-history-btn').addEventListener('click', async () => {
      const list = document.getElementById('history-list');
      if (list.style.display !== 'none') {
        list.style.display = 'none';
        return;
      }
      const history = await IpcClient.listScanHistory(currentFolderPath);
      renderHistoryList(history);
      list.style.display = 'block';
    });

    const exportStatus = document.getElementById('export-status');
    const doExport = async (format) => {
      exportStatus.textContent = 'exporting…';
      exportStatus.className = 'muted';
      try {
        const result = await IpcClient.exportReport(allFindings, currentSummary, format);
        if (result.cancelled) {
          exportStatus.textContent = '';
        } else {
          exportStatus.textContent = `saved: ${result.filePath}`;
          exportStatus.className = 'ok';
        }
      } catch (err) {
        exportStatus.textContent = 'export failed: ' + err.message;
        exportStatus.className = 'danger';
      }
    };

    document.getElementById('export-md-btn').addEventListener('click', () => doExport('markdown'));
    document.getElementById('export-html-btn').addEventListener('click', () => doExport('html'));
    document.getElementById('export-json-btn').addEventListener('click', () => doExport('json'));
    document.getElementById('export-sarif-btn').addEventListener('click', () => doExport('sarif'));
  }

  // Called from settings.js when the PoC-verification toggle changes, so an
  // already-open results screen picks up the new setting immediately rather
  // than staying stale until the next full scan (show() is the only other
  // place that reads it). No-op if no scan has been shown yet this session.
  async function refreshPocSetting() {
    if (!currentSummary) return;
    const settings = await IpcClient.getSettings();
    pocVerificationEnabled = !!settings.pocVerificationEnabled;
    renderList();
  }

  return { init, show, refreshPocSetting };
})();
