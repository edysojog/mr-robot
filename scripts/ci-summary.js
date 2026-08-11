#!/usr/bin/env node
// Turns the CI security-scan reports (mrrobot-gate.sarif, mrrobot-deps.json)
// into a GitHub Actions job summary -- the markdown panel rendered directly
// on the workflow run's own page. This exists because the SARIF-upload-to-
// code-scanning step is a no-op on a private repo without GitHub Advanced
// Security ("resource not accessible by integration"); this is the reliable
// way to actually see findings without downloading the artifact zip.
const fs = require('fs');

function readJsonSafe(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function sarifToRows(sarif) {
  const results = (sarif && sarif.runs && sarif.runs[0] && sarif.runs[0].results) || [];
  return results.map((r) => ({
    level: r.level,
    ruleId: r.ruleId,
    message: (r.message && r.message.text) || '',
    file: r.locations && r.locations[0] && r.locations[0].physicalLocation.artifactLocation.uri,
    line: r.locations && r.locations[0] && r.locations[0].physicalLocation.region.startLine,
  }));
}

// mrrobot-deps.json is reportExporter.buildReportModel()'s own JSON shape --
// findings grouped by severity, same as what the GUI results screen renders.
function reportModelToRows(model) {
  const rows = [];
  ((model && model.grouped) || []).forEach((group) => {
    group.findings.forEach((f) => rows.push({
      severity: f.severity, title: f.title, file: f.file, line: f.line, source: f.source,
    }));
  });
  return rows;
}

function escapeCell(text) {
  return String(text || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function main() {
  const lines = [];
  lines.push('## MrRobotBot self-scan results');
  lines.push('');

  const gateRows = sarifToRows(readJsonSafe('mrrobot-gate.sarif'));
  lines.push(`### Security gate (Semgrep + Gitleaks) -- ${gateRows.length} finding(s)`);
  lines.push('');
  if (gateRows.length === 0) {
    lines.push('No findings.');
  } else {
    lines.push('| Level | Rule | Location | Message |');
    lines.push('|---|---|---|---|');
    gateRows.forEach((r) => {
      lines.push(`| ${r.level} | ${escapeCell(r.ruleId)} | \`${r.file}:${r.line}\` | ${escapeCell(r.message)} |`);
    });
  }
  lines.push('');

  const depsRows = reportModelToRows(readJsonSafe('mrrobot-deps.json'));
  lines.push(`### Dependency audit -- npm audit + OSV, informational only -- ${depsRows.length} finding(s)`);
  lines.push('');
  if (depsRows.length === 0) {
    lines.push('No findings.');
  } else {
    lines.push('| Severity | Title | File |');
    lines.push('|---|---|---|');
    depsRows.forEach((r) => {
      lines.push(`| ${r.severity} | ${escapeCell(r.title)} | \`${r.file}\` |`);
    });
  }
  lines.push('');

  const output = lines.join('\n') + '\n';
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, output);
  } else {
    process.stdout.write(output);
  }
}

main();
