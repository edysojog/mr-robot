const path = require('path');
const crypto = require('crypto');
const { safeSpawn } = require('./safeSpawn');

const RULE_PACKS = ['p/owasp-top-ten', 'p/secrets', 'p/security-audit'];

// Community rule packs are living registries -- their composition drifts,
// and a rule can quietly disappear from a pack even though it still exists
// and fires fine on its own (verified: python.lang.security.audit.
// dangerous-system-call-audit is not in the current p/security-audit or
// p/python packs, but catches os.system(user_input) when referenced
// directly). Pin individually-verified critical rule IDs here so coverage
// for them doesn't silently regress with the packs -- only add an ID after
// confirming both that it fires standalone and that it's actually missing
// from RULE_PACKS above, not just because it sounds important.
const SAFETY_NET_RULE_IDS = [
  'r/python.lang.security.audit.dangerous-system-call-audit',
];
const OVERALL_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
const PER_RULE_TIMEOUT_SEC = 30;

// Runs a quick `semgrep --version` to detect availability + report the version.
function checkInstalled() {
  return new Promise((resolve) => {
    const child = safeSpawn('semgrep', ['--version']);
    let stdout = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.on('error', () => {
      resolve({ installed: false, version: null });
    });

    child.on('close', (code) => {
      if (code === 0 && stdout.trim()) {
        resolve({ installed: true, version: stdout.trim() });
      } else {
        resolve({ installed: false, version: null });
      }
    });
  });
}

function normalizeSeverity(result) {
  const metaSeverity = result.extra && result.extra.metadata && result.extra.metadata.severity;
  const raw = (metaSeverity || (result.extra && result.extra.severity) || 'INFO').toString().toUpperCase();
  switch (raw) {
    case 'CRITICAL': return 'critical';
    case 'ERROR': return 'high';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'WARNING': return 'medium';
    case 'LOW': return 'low';
    default: return 'info';
  }
}

function makeId(parts) {
  return crypto.createHash('sha1').update(parts.join('|')).digest('hex').slice(0, 16);
}

function toFinding(result, rootDir) {
  // Semgrep reports paths absolute (or relative to its own cwd) depending on
  // how it's invoked -- normalize to the same rootDir-relative form the
  // file walker uses, so LLM findings on the same file can be merged.
  const relFile = path.relative(rootDir, result.path).split(path.sep).join('/');
  const title = (result.check_id || '').split('.').pop() || result.check_id;
  const metadata = (result.extra && result.extra.metadata) || {};

  return {
    id: makeId(['semgrep', relFile, String(result.start.line), result.check_id]),
    source: 'semgrep',
    severity: normalizeSeverity(result),
    title: title.replace(/-/g, ' '),
    description: (result.extra && result.extra.message) || '',
    file: relFile,
    line: result.start.line,
    lineEnd: result.end ? result.end.line : result.start.line,
    ruleId: result.check_id,
    cwe: metadata.cwe ? (Array.isArray(metadata.cwe) ? metadata.cwe : [metadata.cwe]) : undefined,
    owasp: metadata.owasp ? (Array.isArray(metadata.owasp) ? metadata.owasp : [metadata.owasp]) : undefined,
    confidence: metadata.confidence ? metadata.confidence.toString().toLowerCase() : undefined,
  };
}

// Runs Semgrep against rootDir, or against a specific set of absolute file
// paths when targetFiles is given (diff mode) -- rootDir is still used to
// relativize result paths either way. onProgress(message) is called with
// human-readable status lines for the terminal-style progress screen.
function runScan(rootDir, onProgress, targetFiles) {
  const emit = (message) => {
    if (onProgress) onProgress(message);
  };

  return new Promise((resolve, reject) => {
    const args = [];
    [...RULE_PACKS, ...SAFETY_NET_RULE_IDS].forEach((pack) => {
      args.push('--config', pack);
    });
    const targets = targetFiles && targetFiles.length > 0 ? targetFiles : [rootDir];
    args.push('--json', '--quiet', '--metrics=off', '--timeout', String(PER_RULE_TIMEOUT_SEC), ...targets);

    const targetDesc = targetFiles ? `${targetFiles.length} changed file(s)` : rootDir;
    emit(`spawning semgrep with rule packs: ${RULE_PACKS.join(', ')} (target: ${targetDesc})`);
    const child = safeSpawn('semgrep', args);

    let stdout = '';
    let stderr = '';
    let settled = false;

    const killTimer = setTimeout(() => {
      if (!settled) {
        emit('semgrep exceeded the overall time budget — terminating');
        child.kill();
      }
    }, OVERALL_TIMEOUT_MS);

    const heartbeat = setInterval(() => {
      if (!settled) emit('semgrep still running…');
    }, 5000);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (err) => {
      settled = true;
      clearTimeout(killTimer);
      clearInterval(heartbeat);
      reject(new Error(`failed to launch semgrep: ${err.message}`));
    });

    child.on('close', (code) => {
      settled = true;
      clearTimeout(killTimer);
      clearInterval(heartbeat);

      if (!stdout.trim()) {
        reject(new Error(`semgrep produced no output (exit code ${code}). stderr: ${stderr.slice(0, 2000)}`));
        return;
      }

      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch (err) {
        reject(new Error(`failed to parse semgrep JSON output: ${err.message}`));
        return;
      }

      const results = parsed.results || [];
      const findings = results.map((r) => toFinding(r, rootDir));

      const skippedCount = (parsed.errors || []).length;
      if (skippedCount > 0) {
        emit(`${skippedCount} file(s) skipped by semgrep due to parse/rule errors`);
      }

      emit(`semgrep finished: ${findings.length} finding(s) across ${results.length} match(es)`);
      resolve({ findings, skippedCount });
    });
  });
}

module.exports = { checkInstalled, runScan };
