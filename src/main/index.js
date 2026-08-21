const path = require('path');
const { app, BrowserWindow } = require('electron');
const { registerFolderHandlers } = require('./ipc/folderHandlers');
const { registerSettingsHandlers } = require('./ipc/settingsHandlers');
const { registerScanHandlers } = require('./ipc/scanHandlers');
const { registerReportHandlers } = require('./ipc/reportHandlers');
const { registerBaselineHandlers } = require('./ipc/baselineHandlers');
const { registerHistoryHandlers } = require('./ipc/historyHandlers');
const { registerHookHandlers } = require('./ipc/hookHandlers');
const { registerChatHandlers } = require('./ipc/chatHandlers');
const { registerFixHandlers } = require('./ipc/fixHandlers');

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 760,
    minHeight: 520,
    backgroundColor: '#0b0f0c',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  registerFolderHandlers();
  registerSettingsHandlers();
  registerScanHandlers();
  registerReportHandlers();
  registerBaselineHandlers();
  registerHistoryHandlers();
  registerHookHandlers();
  registerChatHandlers();
  registerFixHandlers();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
