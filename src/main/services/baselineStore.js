const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASELINE_FILENAME = '.mrrobotbot-baseline.json';

function baselineFilePath(rootDir) {
  return path.join(rootDir, BASELINE_FILENAME);
}

// Stable across line drift from later edits -- keyed on file + rule (or
// title, for AI findings without a ruleId) + severity, not the exact line.
// Meant to be committed alongside the code so a team shares suppressions.
function fingerprint(finding) {
  const normalizedFile = finding.file.trim().replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
  const ruleKey = (finding.ruleId || finding.title || '').trim().toLowerCase();
  return crypto.createHash('sha1').update(`${normalizedFile}::${ruleKey}::${finding.severity}`).digest('hex').slice(0, 16);
}

function readBaseline(rootDir) {
  try {
    const parsed = JSON.parse(fs.readFileSync(baselineFilePath(rootDir), 'utf8'));
    return Array.isArray(parsed.suppressions) ? parsed : { suppressions: [] };
  } catch {
    return { suppressions: [] };
  }
}

function writeBaseline(rootDir, baseline) {
  fs.writeFileSync(baselineFilePath(rootDir), JSON.stringify(baseline, null, 2));
}

function listSuppressions(rootDir) {
  return readBaseline(rootDir).suppressions;
}

function addSuppression(rootDir, finding, reason) {
  const baseline = readBaseline(rootDir);
  const fp = fingerprint(finding);
  if (baseline.suppressions.some((s) => s.fingerprint === fp)) return;

  baseline.suppressions.push({
    fingerprint: fp,
    title: finding.title,
    file: finding.file,
    severity: finding.severity,
    ruleId: finding.ruleId,
    reason: reason || '',
    addedAt: new Date().toISOString(),
  });
  writeBaseline(rootDir, baseline);
}

function removeSuppression(rootDir, fp) {
  const baseline = readBaseline(rootDir);
  baseline.suppressions = baseline.suppressions.filter((s) => s.fingerprint !== fp);
  writeBaseline(rootDir, baseline);
}

function filterSuppressed(rootDir, findings) {
  const suppressedFingerprints = new Set(listSuppressions(rootDir).map((s) => s.fingerprint));
  const kept = [];
  let suppressedCount = 0;

  findings.forEach((f) => {
    if (suppressedFingerprints.has(fingerprint(f))) {
      suppressedCount += 1;
    } else {
      kept.push(f);
    }
  });

  return { kept, suppressedCount };
}

module.exports = {
  fingerprint,
  listSuppressions,
  addSuppression,
  removeSuppression,
  filterSuppressed,
};
