const fs = require('fs');
const { ipcMain, dialog, BrowserWindow } = require('electron');
const { CHANNELS } = require('../../shared/types');
const reportExporter = require('../services/reportExporter');

const FORMAT_CONFIG = {
  json: { ext: 'json', filterName: 'JSON', build: reportExporter.toJson },
  markdown: { ext: 'md', filterName: 'Markdown', build: reportExporter.toMarkdown },
  html: { ext: 'html', filterName: 'HTML', build: reportExporter.toHtml },
  sarif: { ext: 'sarif', filterName: 'SARIF', build: reportExporter.toSarif },
};

function registerReportHandlers() {
  ipcMain.handle(CHANNELS.REPORT_EXPORT, async (event, findings, summary, format) => {
    const config = FORMAT_CONFIG[format];
    if (!config) throw new Error(`Unknown export format: ${format}`);

    const win = BrowserWindow.fromWebContents(event.sender);
    const defaultName = `mrrobotbot-report-${new Date().toISOString().slice(0, 10)}.${config.ext}`;

    const result = await dialog.showSaveDialog(win, {
      defaultPath: defaultName,
      filters: [{ name: config.filterName, extensions: [config.ext] }],
    });
    if (result.canceled || !result.filePath) return { ok: false, cancelled: true };

    const model = reportExporter.buildReportModel(findings, summary);
    const content = config.build(model);
    fs.writeFileSync(result.filePath, content, 'utf8');

    return { ok: true, filePath: result.filePath };
  });
}

module.exports = { registerReportHandlers };
