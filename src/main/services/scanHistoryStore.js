const fs = require('fs');
const path = require('path');
const { app } = require('electron');

const MAX_HISTORY_PER_PROJECT = 50;
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function historyFilePath() {
  return path.join(app.getPath('userData'), 'scanHistory.json');
}

function normalizeRootDir(rootDir) {
  return rootDir.trim().replace(/\\/g, '/').toLowerCase();
}

function readAll() {
  try {
    return JSON.parse(fs.readFileSync(historyFilePath(), 'utf8'));
  } catch {
    return {};
  }
}

function writeAll(data) {
  fs.writeFileSync(historyFilePath(), JSON.stringify(data, null, 2));
}

function countBySeverity(findings) {
  const counts = SEVERITY_ORDER.reduce((acc, sev) => ({ ...acc, [sev]: 0 }), {});
  findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  return counts;
}

// Newest-first.
function getHistory(rootDir) {
  const all = readAll();
  return all[normalizeRootDir(rootDir)] || [];
}

function recordScan(rootDir, findings, summary) {
  const all = readAll();
  const key = normalizeRootDir(rootDir);
  const existing = all[key] || [];

  const entry = {
    timestamp: summary.completedAt,
    findingCount: findings.length,
    counts: countBySeverity(findings),
    confirmedCount: findings.filter((f) => f.source === 'both').length,
    suppressedCount: summary.suppressedCount || 0,
    diffMode: !!summary.diffMode,
    changedFileCount: summary.changedFileCount,
  };

  all[key] = [entry, ...existing].slice(0, MAX_HISTORY_PER_PROJECT);
  writeAll(all);
  return entry;
}

module.exports = { getHistory, recordScan };
