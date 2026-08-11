const ScanProgressScreen = (() => {
  let currentScanId = null;

  // A blinking cursor row stays pinned to the end of the log while a scan is
  // running, terminal-style -- appendLog always inserts new lines before it
  // rather than after, so it stays put at the bottom.
  function addCursor() {
    const log = document.getElementById('scan-log');
    const cursor = document.createElement('div');
    cursor.id = 'scan-log-cursor';
    cursor.className = 'log-cursor';
    log.appendChild(cursor);
  }

  function removeCursor() {
    const cursor = document.getElementById('scan-log-cursor');
    if (cursor) cursor.remove();
  }

  function appendLog(message) {
    const log = document.getElementById('scan-log');
    const line = document.createElement('div');
    const time = new Date().toLocaleTimeString();
    line.textContent = `[${time}] ${message}`;
    const cursor = document.getElementById('scan-log-cursor');
    if (cursor) log.insertBefore(line, cursor); else log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  async function start(folderPath, diffMode, tools) {
    document.getElementById('scan-log').innerHTML = '';
    document.getElementById('scan-folder-path').textContent = folderPath + (diffMode ? ' (diff mode)' : '');
    AppState.show('screen-scan');
    Typewriter.play('#screen-scan');
    addCursor();
    appendLog(diffMode ? `starting diff-mode scan of ${folderPath}` : `starting scan of ${folderPath}`);

    const { scanId } = await IpcClient.startScan(folderPath, diffMode, tools);
    currentScanId = scanId;
  }

  function init() {
    IpcClient.onScanProgress((payload) => {
      if (payload.scanId !== currentScanId) return;
      appendLog(payload.message);
    });

    IpcClient.onScanComplete((payload) => {
      if (payload.scanId !== currentScanId) return;
      if (payload.summary.diffMode && payload.summary.changedFileCount === 0) {
        appendLog('no changed files since the last commit — nothing to scan');
      } else {
        appendLog(`scan complete — ${payload.findings.length} finding(s)`);
      }
      removeCursor();
      ResultsScreen.show(payload.findings, payload.summary);
    });

    IpcClient.onScanError((payload) => {
      if (payload.scanId !== currentScanId) return;
      appendLog(`ERROR: ${payload.message}`);
      removeCursor();
      document.getElementById('start-scan-btn').disabled = false;
    });

    document.getElementById('cancel-scan-btn').addEventListener('click', async () => {
      if (!currentScanId) return;
      appendLog('cancelling…');
      removeCursor();
      await IpcClient.cancelScan(currentScanId);
      AppState.show('screen-folder');
      FolderSelectScreen.refreshStatus();
    });
  }

  return { init, start };
})();
