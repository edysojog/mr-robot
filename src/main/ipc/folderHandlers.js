const fs = require('fs');
const path = require('path');
const { ipcMain, dialog, shell } = require('electron');
const { CHANNELS } = require('../../shared/types');
const fileWalker = require('../services/fileWalker');
const localSettings = require('../services/localSettings');
const gitDiff = require('../services/gitDiff');
const npmAuditRunner = require('../services/npmAuditRunner');

async function walkAndSummarize(rootDir) {
  const [inventory, isGitRepo] = await Promise.all([
    fileWalker.walk(rootDir),
    gitDiff.isGitRepo(rootDir),
  ]);
  const changedFileCount = isGitRepo ? (await gitDiff.getChangedFiles(rootDir)).length : 0;

  return {
    rootDir,
    fileCount: inventory.fileCount,
    totalBytes: inventory.totalBytes,
    truncated: inventory.truncated,
    isGitRepo,
    changedFileCount,
    hasPackageJson: npmAuditRunner.isApplicable(rootDir),
  };
}

function registerFolderHandlers() {
  ipcMain.handle(CHANNELS.PICK_FOLDER, async (event) => {
    const win = require('electron').BrowserWindow.fromWebContents(event.sender);
    const result = await dialog.showOpenDialog(win, {
      properties: ['openDirectory'],
    });
    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }
    const rootDir = result.filePaths[0];
    localSettings.addRecentFolder(rootDir);
    return walkAndSummarize(rootDir);
  });

  ipcMain.handle(CHANNELS.SELECT_RECENT_FOLDER, async (event, rootDir) => {
    if (!fs.existsSync(rootDir)) {
      localSettings.removeRecentFolder(rootDir);
      return null;
    }
    localSettings.addRecentFolder(rootDir);
    return walkAndSummarize(rootDir);
  });

  ipcMain.handle(CHANNELS.OPEN_FILE, async (event, rootDir, relativeFile) => {
    const resolvedRoot = path.resolve(rootDir);
    const target = path.resolve(resolvedRoot, relativeFile);

    // Findings can carry a Claude-generated file path -- keep it inside the
    // scanned folder rather than trusting it to open anything on disk.
    if (target !== resolvedRoot && !target.startsWith(resolvedRoot + path.sep)) {
      throw new Error('Refusing to open a path outside the scanned folder.');
    }

    const error = await shell.openPath(target);
    if (error) throw new Error(error);
    return { ok: true };
  });
}

module.exports = { registerFolderHandlers };
