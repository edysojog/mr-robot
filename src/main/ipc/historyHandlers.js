const { ipcMain } = require('electron');
const { CHANNELS } = require('../../shared/types');
const scanHistoryStore = require('../services/scanHistoryStore');

function registerHistoryHandlers() {
  ipcMain.handle(CHANNELS.HISTORY_LIST, async (event, rootDir) => {
    return scanHistoryStore.getHistory(rootDir);
  });
}

module.exports = { registerHistoryHandlers };
