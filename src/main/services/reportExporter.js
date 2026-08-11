const { version: TOOL_VERSION } = require('../../../package.json');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildReportModel(findings, summary) {
  const counts = SEVERITY_ORDER.reduce((acc, sev) => ({ ...acc, [sev]: 0 }), {});
  findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  const grouped = SEVERITY_ORDER.map((severity) => ({
    severity,
    findings: findings.filter((f) => f.severity === severity),
  })).filter((g) => g.findings.length > 0);

  return {
    folderPath: summary.folderPath,
    completedAt: summary.completedAt,
    skippedCount: summary.skippedCount,
    claudePartial: summary.claudePartial,
    totalFindings: findings.length,
    confirmedByBoth: findings.filter((f) => f.source === 'both').length,
    counts,
    grouped,
  };
}

function toJson(model) {
  return JSON.stringify(model, null, 2);
}

function toMarkdown(model) {
  const lines = [];
  lines.push(`# MrRobotBot Security Report`);
  lines.push('');
  lines.push(`- **Folder:** ${model.folderPath}`);
  lines.push(`- **Scanned:** ${model.completedAt}`);
  lines.push(`- **Total findings:** ${model.totalFindings}`);
  lines.push(`- **Confirmed by both passes:** ${model.confirmedByBoth}`);
  if (model.claudePartial) lines.push(`- **Note:** Claude pass hit its batch cap; some files were not analyzed.`);
  lines.push('');
  lines.push(SEVERITY_ORDER.map((sev) => `${sev}: ${model.counts[sev]}`).join(' | '));
  lines.push('');

  model.grouped.forEach((group) => {
    lines.push(`## ${group.severity.toUpperCase()}`);
    lines.push('');
    group.findings.forEach((f) => {
      lines.push(`### ${f.title}${f.source === 'both' ? ' (confirmed by both passes)' : ''}${f.verified ? ' (verified)' : ''}`);
      lines.push('');
      lines.push(`| | |`);
      lines.push(`|---|---|`);
      lines.push(`| file | \`${f.file}:${f.line}\` |`);
      lines.push(`| source | ${f.source} |`);
      if (f.ruleId) lines.push(`| rule | ${f.ruleId} |`);
      if (f.confidence) lines.push(`| confidence | ${f.confidence} |`);
      if (f.cwe) lines.push(`| cwe | ${f.cwe.join(', ')} |`);
      if (f.owasp) lines.push(`| owasp | ${f.owasp.join(', ')} |`);
      lines.push('');
      lines.push(f.description || '');
      if (f.verifierReason) {
        lines.push('');
        lines.push(`_Verifier note: ${f.verifierReason}_`);
      }
      lines.push('');
    });
  });

  return lines.join('\n');
}

function toHtml(model) {
  const severityColor = {
    critical: '#ff3b3b', high: '#ff5f56', medium: '#ffbd4a', low: '#6fb1ff', info: '#6b8f79',
  };

  const groupsHtml = model.grouped.map((group) => `
    <h2 style="color:${severityColor[group.severity]};text-transform:uppercase;">${group.severity}</h2>
    ${group.findings.map((f) => `
      <details style="border:1px solid #1e2b23;border-left:4px solid ${severityColor[f.severity]};border-radius:4px;padding:10px 14px;margin-bottom:8px;background:#101613;">
        <summary style="cursor:pointer;color:#c9f7d8;">
          <strong>${escapeHtml(f.title)}</strong>
          ${f.source === 'both' ? '<span style="border:1px solid #1f8a4c;color:#39ff88;border-radius:3px;padding:1px 6px;font-size:10px;margin-left:6px;">confirmed</span>' : ''}
          ${f.verified ? '<span style="border:1px solid #1f8a4c;color:#39ff88;border-radius:3px;padding:1px 6px;font-size:10px;margin-left:6px;">verified</span>' : ''}
          <span style="color:#6b8f79;float:right;">${escapeHtml(f.file)}:${f.line}</span>
        </summary>
        <div style="margin-top:10px;padding-top:10px;border-top:1px solid #1e2b23;">
          <p>${escapeHtml(f.description || '')}</p>
          <div>
            <span style="border:1px solid #1e2b23;border-radius:3px;padding:1px 6px;font-size:10px;color:#6b8f79;">source: ${f.source}</span>
            ${f.ruleId ? `<span style="border:1px solid #1e2b23;border-radius:3px;padding:1px 6px;font-size:10px;color:#6b8f79;margin-left:6px;">${escapeHtml(f.ruleId)}</span>` : ''}
            ${f.confidence ? `<span style="border:1px solid #1e2b23;border-radius:3px;padding:1px 6px;font-size:10px;color:#6b8f79;margin-left:6px;">confidence: ${f.confidence}</span>` : ''}
          </div>
          ${f.verifierReason ? `<p style="color:#6b8f79;font-size:12px;margin-top:8px;">verifier note: ${escapeHtml(f.verifierReason)}</p>` : ''}
        </div>
      </details>
    `).join('')}
  `).join('');

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>MrRobotBot Security Report</title>
</head>
<body style="background:#0b0f0c;color:#c9f7d8;font-family:'Cascadia Code','JetBrains Mono',Consolas,monospace;padding:24px;max-width:900px;margin:0 auto;">
  <h1 style="color:#39ff88;">MrRobotBot Security Report</h1>
  <p><strong>Folder:</strong> ${escapeHtml(model.folderPath)}<br/>
  <strong>Scanned:</strong> ${escapeHtml(model.completedAt)}<br/>
  <strong>Total findings:</strong> ${model.totalFindings} &nbsp; <strong>Confirmed by both passes:</strong> ${model.confirmedByBoth}</p>
  ${model.claudePartial ? '<p style="color:#ffbd4a;">Claude pass hit its batch cap; some files were not analyzed.</p>' : ''}
  ${groupsHtml}
</body>
</html>`;
}

// SARIF (Static Analysis Results Interchange Format) 2.1.0 -- the format
// GitHub/GitLab code-scanning ingest, so a scan can gate a PR instead of
// being a manual-only report. One "rule" per distinct check (Semgrep
// ruleId, secret pattern, npm package, or a slugified AI finding title),
// referenced by every result that matched it.
function slugify(text) {
  return String(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'finding';
}

function severityToSarifLevel(severity) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

// GitHub's code-scanning UI reads security-severity (a 0-10 CVSS-like
// score) to color/sort alerts -- SARIF's own level is coarser.
function severityScore(severity) {
  return { critical: '9.0', high: '7.0', medium: '5.0', low: '3.0', info: '1.0' }[severity] || '1.0';
}

function toSarif(model) {
  const rules = new Map();
  const results = [];

  model.grouped.forEach((group) => {
    group.findings.forEach((f) => {
      const ruleId = f.ruleId || `mrrobotbot/${slugify(f.title)}`;
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: f.title,
          shortDescription: { text: f.title },
          fullDescription: { text: f.description || f.title },
          properties: { 'security-severity': severityScore(f.severity), tags: ['security', f.source] },
        });
      }

      results.push({
        ruleId,
        level: severityToSarifLevel(f.severity),
        message: { text: f.description || f.title },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line || 1, endLine: f.lineEnd || f.line || 1 },
          },
        }],
        properties: { source: f.source, confidence: f.confidence },
      });
    });
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'MrRobotBot',
          version: TOOL_VERSION,
          rules: Array.from(rules.values()),
        },
      },
      results,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

module.exports = { buildReportModel, toJson, toMarkdown, toHtml, toSarif };
