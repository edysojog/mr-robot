const { test } = require('node:test');
const assert = require('node:assert/strict');
const reportExporter = require('../src/main/services/reportExporter');

const summary = { folderPath: '/repo', completedAt: '2026-08-11T00:00:00.000Z', skippedCount: 0, claudePartial: false };

function finding(overrides = {}) {
  return {
    id: 'f1',
    source: 'semgrep',
    severity: 'high',
    title: 'SQL injection',
    description: 'user input reaches a raw query',
    file: 'src/app.js',
    line: 10,
    lineEnd: 10,
    ruleId: 'sql-injection',
    confidence: 'high',
    ...overrides,
  };
}

test('buildReportModel: counts findings per severity and groups only non-empty severities', () => {
  const model = reportExporter.buildReportModel(
    [finding({ severity: 'critical' }), finding({ severity: 'critical' }), finding({ severity: 'low' })],
    summary,
  );

  assert.equal(model.totalFindings, 3);
  assert.equal(model.counts.critical, 2);
  assert.equal(model.counts.low, 1);
  assert.equal(model.counts.high, 0);
  assert.deepEqual(model.grouped.map((g) => g.severity), ['critical', 'low']);
});

test('buildReportModel: confirmedByBoth only counts source === "both"', () => {
  const model = reportExporter.buildReportModel(
    [finding({ source: 'both' }), finding({ source: 'semgrep' }), finding({ source: 'both' })],
    summary,
  );
  assert.equal(model.confirmedByBoth, 2);
});

test('toJson: round-trips the report model', () => {
  const model = reportExporter.buildReportModel([finding()], summary);
  const parsed = JSON.parse(reportExporter.toJson(model));
  assert.equal(parsed.totalFindings, 1);
});

test('toMarkdown: names the specific static tool for a "both" finding, not a generic label', () => {
  const model = reportExporter.buildReportModel(
    [finding({ source: 'both', staticSource: 'gitleaks' })],
    summary,
  );
  const md = reportExporter.toMarkdown(model);
  assert.match(md, /confirmed by gitleaks \+ ai/);
});

test('toHtml: escapes finding titles to prevent HTML injection', () => {
  const model = reportExporter.buildReportModel(
    [finding({ title: '<script>alert(1)</script>' })],
    summary,
  );
  const html = reportExporter.toHtml(model);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('toSarif: produces one rule per distinct ruleId and a matching result location', () => {
  const model = reportExporter.buildReportModel(
    [finding({ ruleId: 'sql-injection', file: 'src/app.js', line: 10 })],
    summary,
  );
  const sarif = JSON.parse(reportExporter.toSarif(model));

  assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, 'sql-injection');
  const result = sarif.runs[0].results[0];
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/app.js');
  assert.equal(result.locations[0].physicalLocation.region.startLine, 10);
});

test('toSarif: severity maps to the correct SARIF level (critical/high -> error, medium -> warning, low/info -> note)', () => {
  const model = reportExporter.buildReportModel(
    [
      finding({ severity: 'critical', file: 'a.js' }),
      finding({ severity: 'medium', file: 'b.js' }),
      finding({ severity: 'low', file: 'c.js' }),
    ],
    summary,
  );
  const sarif = JSON.parse(reportExporter.toSarif(model));
  const levelByFile = Object.fromEntries(
    sarif.runs[0].results.map((r) => [r.locations[0].physicalLocation.artifactLocation.uri, r.level]),
  );
  assert.equal(levelByFile['a.js'], 'error');
  assert.equal(levelByFile['b.js'], 'warning');
  assert.equal(levelByFile['c.js'], 'note');
});
