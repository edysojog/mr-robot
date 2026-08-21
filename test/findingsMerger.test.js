const { test } = require('node:test');
const assert = require('node:assert/strict');
const findingsMerger = require('../src/main/services/findingsMerger');

function staticFinding(overrides = {}) {
  return {
    id: 's1',
    source: 'semgrep',
    severity: 'medium',
    title: 'SQL injection',
    description: 'static description',
    file: 'src/app.js',
    line: 42,
    confidence: 'medium',
    ...overrides,
  };
}

function aiFinding(overrides = {}) {
  return {
    id: 'a1',
    source: 'claude',
    severity: 'high',
    title: 'SQL injection via string concat',
    description: 'ai description with more detail',
    file: 'src/app.js',
    line: 43,
    confidence: 'high',
    ...overrides,
  };
}

test('findingsMerger: matching file + nearby line merges into one "both" finding', () => {
  const merged = findingsMerger.merge([staticFinding()], [aiFinding()]);

  assert.equal(merged.length, 1);
  assert.equal(merged[0].source, 'both');
});

test('findingsMerger: merged finding escalates to the higher severity of the two', () => {
  const merged = findingsMerger.merge(
    [staticFinding({ severity: 'medium' })],
    [aiFinding({ severity: 'critical' })],
  );

  assert.equal(merged[0].severity, 'critical');
});

test('findingsMerger: merged finding keeps the AI description over the static one', () => {
  const merged = findingsMerger.merge([staticFinding()], [aiFinding()]);

  assert.equal(merged[0].description, 'ai description with more detail');
});

test('findingsMerger: staticSource records which static tool actually matched, not just "semgrep"', () => {
  const merged = findingsMerger.merge(
    [staticFinding({ source: 'gitleaks' })],
    [aiFinding()],
  );

  assert.equal(merged[0].source, 'both');
  assert.equal(merged[0].staticSource, 'gitleaks');
});

test('findingsMerger: findings more than 3 lines apart are not merged', () => {
  const merged = findingsMerger.merge(
    [staticFinding({ line: 10 })],
    [aiFinding({ line: 20 })],
  );

  assert.equal(merged.length, 2);
  assert.ok(merged.every((f) => f.source !== 'both'));
});

test('findingsMerger: findings in different files are never merged, even at the same line', () => {
  const merged = findingsMerger.merge(
    [staticFinding({ file: 'src/a.js', line: 10 })],
    [aiFinding({ file: 'src/b.js', line: 10 })],
  );

  assert.equal(merged.length, 2);
});

test('findingsMerger: unmatched static and AI findings both pass through untouched', () => {
  const merged = findingsMerger.merge(
    [staticFinding({ id: 's1', line: 10 })],
    [aiFinding({ id: 'a1', line: 500 })],
  );

  assert.equal(merged.length, 2);
  assert.ok(merged.some((f) => f.id === 's1'));
  assert.ok(merged.some((f) => f.id === 'a1'));
});

test('findingsMerger: results are ranked by severity, then "both" before single-source, then filename', () => {
  const merged = findingsMerger.merge(
    [
      staticFinding({ id: 'low1', file: 'z.js', line: 1, severity: 'low' }),
      staticFinding({ id: 'crit-static', file: 'b.js', line: 1, severity: 'critical' }),
    ],
    [
      aiFinding({ id: 'crit-ai-unmatched', file: 'a.js', line: 900, severity: 'critical' }),
    ],
  );

  assert.equal(merged[0].severity, 'critical');
  assert.equal(merged[1].severity, 'critical');
  assert.equal(merged[2].severity, 'low');
});
