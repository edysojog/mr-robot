const { test } = require('node:test');
const assert = require('node:assert/strict');
const osvRunner = require('../src/main/services/osvRunner');

test('osvRunner.parseRequirementsTxt: picks up exact pins', () => {
  const content = 'PyYAML==5.1\nDjango==1.11.0\n';
  const deps = osvRunner.parseRequirementsTxt(content, 'requirements.txt');

  assert.equal(deps.length, 2);
  assert.deepEqual(deps[0], { ecosystem: 'PyPI', name: 'PyYAML', version: '5.1', file: 'requirements.txt', line: 1 });
  assert.equal(deps[1].name, 'Django');
});

test('osvRunner.parseRequirementsTxt: skips unpinned ranges -- no single version to check', () => {
  const deps = osvRunner.parseRequirementsTxt('requests>=2.0\nflask~=2.3\n', 'requirements.txt');
  assert.equal(deps.length, 0);
});

test('osvRunner.parseRequirementsTxt: ignores comments and blank lines', () => {
  const content = '# a comment\n\nPyYAML==5.1  # inline comment\n';
  const deps = osvRunner.parseRequirementsTxt(content, 'requirements.txt');

  assert.equal(deps.length, 1);
  assert.equal(deps[0].version, '5.1');
});

test('osvRunner.parseGoMod: matches require-block entries', () => {
  const content = [
    'module example.com/app',
    '',
    'require (',
    '\tgithub.com/foo/bar v1.2.3',
    '\tgithub.com/baz/qux v0.0.1 // indirect',
    ')',
  ].join('\n');
  const deps = osvRunner.parseGoMod(content, 'go.mod');

  assert.equal(deps.length, 2);
  assert.equal(deps[0].ecosystem, 'Go');
  assert.equal(deps[0].name, 'github.com/foo/bar');
  assert.equal(deps[0].version, 'v1.2.3');
  assert.equal(deps[1].name, 'github.com/baz/qux');
});

test('osvRunner.parseGoMod: matches the single-line require form', () => {
  const deps = osvRunner.parseGoMod('require github.com/foo/bar v1.2.3\n', 'go.mod');
  assert.equal(deps.length, 1);
  assert.equal(deps[0].version, 'v1.2.3');
});

test('osvRunner.parseCargoLock: reads name/version out of [[package]] blocks', () => {
  const content = [
    '[[package]]',
    'name = "serde"',
    'version = "1.0.100"',
    '',
    '[[package]]',
    'name = "tokio"',
    'version = "1.28.0"',
  ].join('\n');
  const deps = osvRunner.parseCargoLock(content, 'Cargo.lock');

  assert.equal(deps.length, 2);
  assert.equal(deps[0].ecosystem, 'crates.io');
  assert.equal(deps[0].name, 'serde');
  assert.equal(deps[1].name, 'tokio');
});

test('osvRunner.normalizeSeverity: maps "moderate" to "medium"', () => {
  assert.equal(osvRunner.normalizeSeverity({ database_specific: { severity: 'MODERATE' } }), 'medium');
});

test('osvRunner.normalizeSeverity: passes through a known severity string', () => {
  assert.equal(osvRunner.normalizeSeverity({ database_specific: { severity: 'critical' } }), 'critical');
});

test('osvRunner.normalizeSeverity: defaults to medium rather than hiding an unranked real vulnerability under "low"', () => {
  assert.equal(osvRunner.normalizeSeverity({}), 'medium');
});

test('osvRunner.toFinding: rolls up every advisory for a dependency into a single finding at the worst severity', () => {
  const dep = { name: 'Django', version: '1.11.0', file: 'requirements.txt', line: 2 };
  const vulns = [
    { id: 'GHSA-1', database_specific: { severity: 'low' }, summary: 'minor issue' },
    { id: 'GHSA-2', database_specific: { severity: 'critical' }, summary: 'major issue' },
  ];
  const finding = osvRunner.toFinding(dep, vulns);

  assert.equal(finding.severity, 'critical');
  assert.equal(finding.source, 'osv');
  assert.match(finding.title, /2 advisories/);
  assert.match(finding.description, /GHSA-1/);
  assert.match(finding.description, /GHSA-2/);
});
