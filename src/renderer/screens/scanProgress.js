const ScanProgressScreen = (() => {
  let currentScanId = null;

  function appendLog(message) {
    const log = document.getElementById('scan-log');
    const line = document.createElement('div');
    const time = new Date().toLocaleTimeString();
    line.textContent = `[${time}] ${message}`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  async function start(folderPath, diffMode, tools) {
    document.getElementById('scan-log').innerHTML = '';
    document.getElementById('scan-folder-path').textContent = folderPath + (diffMode ? ' (diff mode)' : '');
    AppState.show('screen-scan');
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
      ResultsScreen.show(payload.findings, payload.summary);
    });

    IpcClient.onScanError((payload) => {
      if (payload.scanId !== currentScanId) return;
      appendLog(`ERROR: ${payload.message}`);
      document.getElementById('start-scan-btn').disabled = false;
    });

    document.getElementById('cancel-scan-btn').addEventListener('click', async () => {
      if (!currentScanId) return;
      appendLog('cancelling…');
      await IpcClient.cancelScan(currentScanId);
      AppState.show('screen-folder');
      FolderSelectScreen.refreshStatus();
    });
  }

  return { init, start };
})();
