const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const OVERALL_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutes

function checkInstalled() {
  return new Promise((resolve) => {
    const child = spawn('npm', ['--version'], { shell: true });
    let stdout = '';

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.on('error', () => resolve({ installed: false, version: null }));
    child.on('close', (code) => {
      if (code === 0 && stdout.trim()) {
        resolve({ installed: true, version: stdout.trim() });
      } else {
        resolve({ installed: false, version: null });
      }
    });
  });
}

// npm audit only applies to Node projects -- unlike Semgrep/Gitleaks there's
// nothing useful to run without a package.json in the scanned folder.
function isApplicable(rootDir) {
  return fs.existsSync(path.join(rootDir, 'package.json'));
}

function makeId(parts) {
  return crypto.createHash('sha1').update(parts.join('|')).digest('hex').slice(0, 16);
}

function normalizeSeverity(raw) {
  const s = (raw || 'low').toString().toLowerCase();
  if (s === 'moderate') return 'medium';
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

function describeAdvisories(via) {
  return (via || [])
    .filter((v) => typeof v === 'object' && v !== null)
    .map((v) => `${v.title || v.name || 'advisory'}${v.url ? ` (${v.url})` : ''}`)
    .join('; ');
}

// npm audit reports at the dependency level, not a line of code -- findings
// are anchored to package.json since that's the actual file a fix touches.
function toFinding(pkgName, vuln, rootDir) {
  const severity = normalizeSeverity(vuln.severity);
  const advisoryText = describeAdvisories(vuln.via);

  return {
    id: makeId(['npm-audit', pkgName, severity]),
    source: 'npm-audit',
    severity,
    title: `${pkgName}: ${severity} severity dependency vulnerability`,
    description: advisoryText || `${pkgName} has a known ${severity} severity vulnerability in range ${vuln.range || 'unknown'}.${vuln.fixAvailable ? ' A fix is available via npm audit fix.' : ''}`,
    file: 'package.json',
    line: 1,
    lineEnd: 1,
    ruleId: pkgName,
    confidence: 'high',
  };
}

function runScan(rootDir, onProgress) {
  const emit = (message) => { if (onProgress) onProgress(message); };

  return new Promise((resolve, reject) => {
    if (!isApplicable(rootDir)) {
      emit('npm audit skipped — no package.json in this folder');
      resolve({ findings: [] });
      return;
    }

    emit(`spawning npm audit in ${rootDir}`);
    const child = spawn('npm', ['audit', '--json'], { cwd: rootDir, shell: true });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const killTimer = setTimeout(() => {
      if (!settled) {
        emit('npm audit exceeded the time budget — terminating');
        child.kill();
      }
    }, OVERALL_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    child.on('error', (err) => {
      settled = true;
      clearTimeout(killTimer);
      reject(new Error(`failed to launch npm audit: ${err.message}`));
    });

    child.on('close', () => {
      settled = true;
      clearTimeout(killTimer);

      // npm audit exits non-zero when vulnerabilities are found -- that's
      // expected, not a failure, as long as it printed JSON.
      if (!stdout.trim()) {
        reject(new Error(`npm audit produced no output. stderr: ${stderr.slice(0, 2000)}`));
        return;
      }

      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch (err) {
        reject(new Error(`failed to parse npm audit JSON output: ${err.message}`));
        return;
      }

      const vulnerabilities = parsed.vulnerabilities || {};
      const findings = Object.entries(vulnerabilities).map(([pkgName, vuln]) => toFinding(pkgName, vuln, rootDir));

      emit(`npm audit finished: ${findings.length} finding(s)`);
      resolve({ findings });
    });
  });
}

module.exports = { checkInstalled, isApplicable, runScan, normalizeSeverity, toFinding };
