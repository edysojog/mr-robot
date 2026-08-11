const { ipcMain } = require('electron');
const { CHANNELS } = require('../../shared/types');
const baselineStore = require('../services/baselineStore');

function registerBaselineHandlers() {
  ipcMain.handle(CHANNELS.BASELINE_SUPPRESS, async (event, rootDir, finding, reason) => {
    baselineStore.addSuppression(rootDir, finding, reason);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.BASELINE_UNSUPPRESS, async (event, rootDir, fingerprint) => {
    baselineStore.removeSuppression(rootDir, fingerprint);
    return { ok: true };
  });

  ipcMain.handle(CHANNELS.BASELINE_LIST, async (event, rootDir) => {
    return baselineStore.listSuppressions(rootDir);
  });
}

module.exports = { registerBaselineHandlers };
