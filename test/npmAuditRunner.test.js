const { test } = require('node:test');
const assert = require('node:assert/strict');
const npmAuditRunner = require('../src/main/services/npmAuditRunner');

test('npmAuditRunner.normalizeSeverity: maps "moderate" to "medium"', () => {
  assert.equal(npmAuditRunner.normalizeSeverity('moderate'), 'medium');
});

test('npmAuditRunner.normalizeSeverity: passes through known severities', () => {
  assert.equal(npmAuditRunner.normalizeSeverity('critical'), 'critical');
  assert.equal(npmAuditRunner.normalizeSeverity('high'), 'high');
  assert.equal(npmAuditRunner.normalizeSeverity('low'), 'low');
});

test('npmAuditRunner.normalizeSeverity: unknown/missing input defaults to low', () => {
  assert.equal(npmAuditRunner.normalizeSeverity(undefined), 'low');
  assert.equal(npmAuditRunner.normalizeSeverity('nonsense'), 'low');
});

test('npmAuditRunner.toFinding: anchors the finding at package.json:1, not a real code line', () => {
  const finding = npmAuditRunner.toFinding('lodash', { severity: 'critical', via: [], range: '<4.17.21' });

  assert.equal(finding.source, 'npm-audit');
  assert.equal(finding.file, 'package.json');
  assert.equal(finding.line, 1);
  assert.equal(finding.ruleId, 'lodash');
  assert.equal(finding.severity, 'critical');
});
