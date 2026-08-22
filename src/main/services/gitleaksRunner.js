const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { safeSpawn } = require('./safeSpawn');
const { EXCLUDED_DIR_NAMES } = require('../constants/excludes');

const OVERALL_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// gitleaks' `detect` command has no built-in directory-exclude flag, so
// build a throwaway config that extends the default ruleset with a global
// allowlist covering the same build-artifact/vendor dirs the file walker
// already skips (node_modules, release, .git, ...). Without this, a
// packaged build (release/win-unpacked/*.pak, embedded Chromium certs)
// gets scanned and produces "generic-api-key" false positives on
// third-party binary resources, not this project's own secrets.
function buildAllowlistConfig() {
  const paths = Array.from(EXCLUDED_DIR_NAMES)
    .map((name) => `  '''(^|[\\\\/])${escapeRegex(name)}([\\\\/]|$)'''`)
    .join(',\n');

  return `[extend]\nuseDefault = true\n\n[allowlist]\npaths = [\n${paths},\n]\n`;
}

function checkInstalled() {
  return new Promise((resolve) => {
    const child = safeSpawn('gitleaks', ['version']);
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

function makeId(parts) {
  return crypto.createHash('sha1').update(parts.join('|')).digest('hex').slice(0, 16);
}

// Gitleaks doesn't emit a severity -- a leaked secret is always treated as
// high regardless of which rule matched.
function toFinding(item, rootDir) {
  const relFile = path.relative(rootDir, item.File || '').split(path.sep).join('/');
  return {
    id: makeId(['gitleaks', relFile, String(item.StartLine), item.RuleID]),
    source: 'gitleaks',
    severity: 'high',
    title: (item.Description || item.RuleID || 'possible secret').toString(),
    description: `Possible ${item.RuleID} match: ${item.Match || item.Secret || ''}`.trim(),
    file: relFile,
    line: item.StartLine,
    lineEnd: item.EndLine || item.StartLine,
    ruleId: item.RuleID,
    confidence: 'medium',
  };
}

// Runs Gitleaks against the whole rootDir working tree. Unlike Semgrep,
// this deliberately ignores diff-mode file scoping -- a secret can leak
// through a file that wasn't part of this change, so it's cheap and safer
// to always check the full tree.
function runScan(rootDir, onProgress) {
  const emit = (message) => { if (onProgress) onProgress(message); };

  return new Promise((resolve, reject) => {
    const reportPath = path.join(os.tmpdir(), `mrrobotbot-gitleaks-${crypto.randomUUID()}.json`);
    const configPath = path.join(os.tmpdir(), `mrrobotbot-gitleaks-config-${crypto.randomUUID()}.toml`);
    fs.writeFileSync(configPath, buildAllowlistConfig(), 'utf8');

    const args = [
      'detect',
      '--source', rootDir,
      '--no-git',
      '--no-banner',
      '--config', configPath,
      '--report-format', 'json',
      '--report-path', reportPath,
      '--exit-code', '0',
    ];

    emit(`spawning gitleaks against ${rootDir}`);
    const child = safeSpawn('gitleaks', args);

    let stderr = '';
    let settled = false;

    const killTimer = setTimeout(() => {
      if (!settled) {
        emit('gitleaks exceeded the time budget — terminating');
        child.kill();
      }
    }, OVERALL_TIMEOUT_MS);

    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    child.on('error', (err) => {
      settled = true;
      clearTimeout(killTimer);
      fs.unlink(configPath, () => {});
      reject(new Error(`failed to launch gitleaks: ${err.message}`));
    });

    child.on('close', (code) => {
      settled = true;
      clearTimeout(killTimer);
      fs.unlink(configPath, () => {});

      if (!fs.existsSync(reportPath)) {
        // Newer gitleaks versions skip writing the report file when there
        // are zero findings -- treat that as a clean scan, not an error.
        emit('gitleaks finished: 0 finding(s)');
        resolve({ findings: [] });
        return;
      }

      let items;
      try {
        const raw = fs.readFileSync(reportPath, 'utf8').trim();
        items = raw ? JSON.parse(raw) : [];
      } catch (err) {
        fs.unlink(reportPath, () => {});
        reject(new Error(`failed to parse gitleaks JSON output: ${err.message}. stderr: ${stderr.slice(0, 1000)}`));
        return;
      }
      fs.unlink(reportPath, () => {});

      const findings = (items || []).map((item) => toFinding(item, rootDir));
      emit(`gitleaks finished: ${findings.length} finding(s)`);
      resolve({ findings });
    });
  });
}

module.exports = { checkInstalled, runScan };
