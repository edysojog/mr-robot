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

// Human-readable report for an interactive terminal -- the other four
// formats are all machine- or file-targeted, which left someone running a
// scan by hand reading raw JSON.
//
// Colour is a caller-supplied flag rather than something detected here, so
// this stays a pure function: the CLI decides based on TTY/NO_COLOR and the
// GUI never asks for colour at all.
const ANSI = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', yellow: '\x1b[33m', blue: '\x1b[34m',
  gray: '\x1b[90m', brightRed: '\x1b[91m', green: '\x1b[32m',
};
const SEVERITY_ANSI = {
  critical: ANSI.brightRed, high: ANSI.red, medium: ANSI.yellow,
  low: ANSI.blue, info: ANSI.gray,
};

// npm audit rolls every advisory for a package into one description -- the
// electron entry in this repo is ~4000 characters. Printed whole it buries
// every other finding, so descriptions are wrapped and capped, with the
// full text still available in the JSON/SARIF formats.
const MAX_DESC_LINES = 3;

function wrapText(text, width) {
  const out = [];
  for (const paragraph of String(text).split('\n')) {
    let line = '';
    for (const word of paragraph.split(/\s+/).filter(Boolean)) {
      const candidate = line ? `${line} ${word}` : word;
      if (candidate.length > width && line) { out.push(line); line = word; }
      else line = candidate;
    }
    if (line) out.push(line);
  }
  return out;
}

function toTerminal(model, options = {}) {
  const width = Math.max(40, Math.min(options.width || 100, 100));
  const color = !!options.color;
  const c = (code, s) => (color ? `${code}${s}${ANSI.reset}` : String(s));

  const lines = [];
  lines.push('');
  lines.push(`  ${c(ANSI.bold, 'MrRobotBot')} ${c(ANSI.dim, '·')} ${model.folderPath}`);

  const meta = [
    `${model.totalFindings} finding${model.totalFindings === 1 ? '' : 's'}`,
    `${model.confirmedByBoth} confirmed by both passes`,
    ...(model.skippedCount ? [`${model.skippedCount} file(s) skipped`] : []),
    ...(model.claudePartial ? ['AI pass incomplete'] : []),
  ];
  lines.push(`  ${c(ANSI.dim, meta.join(' · '))}`);

  // Severity tally: zero counts stay dim so the ones that matter stand out.
  const tally = SEVERITY_ORDER.map((sev) => {
    const n = model.counts[sev] || 0;
    return n > 0 ? c(SEVERITY_ANSI[sev], `${sev} ${n}`) : c(ANSI.dim, `${sev} ${n}`);
  }).join(c(ANSI.dim, '   '));
  lines.push(`  ${tally}`);

  if (model.totalFindings === 0) {
    lines.push('');
    lines.push(`  ${c(ANSI.green, 'No findings.')}`);
    lines.push('');
    return lines.join('\n');
  }

  // Numbered continuously across severity groups so the numbering matches
  // the order findings are printed in.
  let n = 0;
  for (const group of model.grouped) {
    lines.push('');
    const heading = group.severity.toUpperCase();
    lines.push(`  ${c(SEVERITY_ANSI[group.severity] + ANSI.bold, heading)} ${c(ANSI.dim, '─'.repeat(Math.max(0, width - heading.length - 4)))}`);

    for (const f of group.findings) {
      n += 1;
      lines.push('');
      lines.push(`  ${c(ANSI.bold, String(n).padStart(2))}  ${f.title}`);

      const tags = [f.source, f.rule].filter(Boolean).join(' · ');
      const location = `${f.file}:${f.line}`;
      lines.push(`      ${c(ANSI.dim, location)}${tags ? c(ANSI.dim, `   ${tags}`) : ''}`);

      if (f.description) {
        const body = wrapText(f.description, width - 6);
        for (const line of body.slice(0, MAX_DESC_LINES)) lines.push(`      ${c(ANSI.dim, line)}`);
        if (body.length > MAX_DESC_LINES) {
          lines.push(`      ${c(ANSI.dim, `… ${body.length - MAX_DESC_LINES} more line(s) -- see --format json`)}`);
        }
      }
    }
  }

  lines.push('');
  return lines.join('\n');
}

module.exports = { buildReportModel, toJson, toMarkdown, toHtml, toSarif, toTerminal };
