const { ipcMain } = require('electron');
const { CHANNELS } = require('../../shared/types');
const preCommitHook = require('../services/preCommitHook');

function registerHookHandlers() {
  ipcMain.handle(CHANNELS.HOOK_STATUS, async (event, rootDir) => {
    return preCommitHook.status(rootDir);
  });

  ipcMain.handle(CHANNELS.HOOK_INSTALL, async (event, rootDir) => {
    return preCommitHook.install(rootDir);
  });

  ipcMain.handle(CHANNELS.HOOK_UNINSTALL, async (event, rootDir) => {
    return preCommitHook.uninstall(rootDir);
  });
}

module.exports = { registerHookHandlers };
