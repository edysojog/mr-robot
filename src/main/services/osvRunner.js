const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Cross-references pinned dependency versions against OSV.dev's public,
// keyless vulnerability database -- the ecosystem-agnostic sibling to
// npmAuditRunner.js, for projects npm audit doesn't cover (Python, Go,
// Rust so far). No local binary, no install, no auth: just an HTTPS call,
// so unlike Semgrep/Gitleaks there's nothing to "check installed".
const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
const OVERALL_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutes
const CONCURRENCY = 6;

function makeId(parts) {
  return crypto.createHash('sha1').update(parts.join('|')).digest('hex').slice(0, 16);
}

// requirements.txt: only exact pins (`pkg==1.2.3`) are checkable -- a range
// like `pkg>=2.0` has no single version OSV can match against, so those
// lines are silently skipped rather than guessed at.
function parseRequirementsTxt(content, file) {
  const deps = [];
  content.split('\n').forEach((rawLine, i) => {
    const line = rawLine.split('#')[0].trim();
    const match = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+-]*)/);
    if (match) deps.push({ ecosystem: 'PyPI', name: match[1], version: match[2], file, line: i + 1 });
  });
  return deps;
}

// go.mod: matches both the single-line form ("require mod v1.2.3") and
// entries inside a require( ... ) block ("mod v1.2.3 // indirect").
function parseGoMod(content, file) {
  const deps = [];
  content.split('\n').forEach((rawLine, i) => {
    const line = rawLine.trim();
    const match = line.match(/^(?:require\s+)?([a-zA-Z0-9][a-zA-Z0-9._~/-]*\.[a-zA-Z]{2,}[a-zA-Z0-9._~/-]*)\s+(v[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9.+-]*)/);
    if (match) deps.push({ ecosystem: 'Go', name: match[1], version: match[2], file, line: i + 1 });
  });
  return deps;
}

// Cargo.lock: TOML [[package]] blocks with name = "..." and version = "...".
function parseCargoLock(content, file) {
  const deps = [];
  let current = null;
  content.split('\n').forEach((rawLine, i) => {
    const line = rawLine.trim();
    if (line === '[[package]]') {
      current = { startLine: i + 1 };
      return;
    }
    if (!current) return;
    const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nameMatch) current.name = nameMatch[1];
    const versionMatch = line.match(/^version\s*=\s*"([^"]+)"/);
    if (versionMatch) current.version = versionMatch[1];
    if (current.name && current.version) {
      deps.push({ ecosystem: 'crates.io', name: current.name, version: current.version, file, line: current.startLine });
      current = null;
    }
  });
  return deps;
}

const MANIFESTS = [
  { file: 'requirements.txt', parse: parseRequirementsTxt },
  { file: 'go.mod', parse: parseGoMod },
  { file: 'Cargo.lock', parse: parseCargoLock },
];

function isApplicable(rootDir) {
  return MANIFESTS.some((m) => fs.existsSync(path.join(rootDir, m.file)));
}

function collectDependencies(rootDir) {
  const deps = [];
  MANIFESTS.forEach((manifest) => {
    const fullPath = path.join(rootDir, manifest.file);
    if (!fs.existsSync(fullPath)) return;
    const content = fs.readFileSync(fullPath, 'utf8');
    deps.push(...manifest.parse(content, manifest.file));
  });
  return deps;
}

async function queryOsv(dep) {
  const res = await fetch(OSV_QUERY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ version: dep.version, package: { name: dep.name, ecosystem: dep.ecosystem } }),
  });
  if (!res.ok) throw new Error(`OSV query failed (HTTP ${res.status})`);
  const data = await res.json();
  return data.vulns || [];
}

// Small worker pool rather than one request per dependency in parallel --
// a project can pin dozens of packages, and OSV's public endpoint has no
// SLA promise for unbounded concurrent bursts from one caller.
async function queryAll(deps, emit) {
  const results = [];
  let index = 0;

  async function worker() {
    while (index < deps.length) {
      const dep = deps[index++];
      try {
        const vulns = await queryOsv(dep);
        if (vulns.length > 0) results.push({ dep, vulns });
      } catch (err) {
        emit(`OSV query failed for ${dep.name}@${dep.version}: ${err.message}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, deps.length) }, worker));
  return results;
}

// Many OSV entries (GHSA-sourced ones especially) carry a plain severity
// string; others only carry a raw CVSS vector, which needs a proper CVSS
// calculator to score -- not worth a new dependency for this. When neither
// is parseable, default to 'medium' rather than 'low': it's a real,
// database-confirmed vulnerability, just one this pass can't rank precisely.
function normalizeSeverity(vuln) {
  const raw = vuln.database_specific && vuln.database_specific.severity;
  if (raw) {
    const s = raw.toString().toLowerCase();
    if (s === 'moderate') return 'medium';
    if (['critical', 'high', 'medium', 'low'].includes(s)) return s;
  }
  return 'medium';
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function higherSeverity(a, b) {
  return SEVERITY_RANK[a] <= SEVERITY_RANK[b] ? a : b;
}

function advisoryId(vuln) {
  return vuln.id || (vuln.aliases && vuln.aliases[0]) || 'advisory';
}

function describeAdvisories(vulns) {
  return vulns
    .map((v) => `${advisoryId(v)}: ${v.summary || v.details || 'known vulnerability'}`)
    .join('; ');
}

// One finding per dependency, not per advisory -- an old pinned version can
// carry a dozen CVEs, and npmAuditRunner.js already established the
// convention of collapsing those into a single per-package finding rather
// than flooding the results list with what reads as duplicates. Severity
// escalates to the worst of the group; every advisory ID is kept in the
// description so nothing is actually lost, just consolidated.
function toFinding(dep, vulns) {
  const severity = vulns.map(normalizeSeverity).reduce(higherSeverity);

  return {
    id: makeId(['osv', dep.name, dep.version]),
    source: 'osv',
    severity,
    title: `${dep.name}@${dep.version}: ${severity} severity dependency vulnerability${vulns.length > 1 ? ` (${vulns.length} advisories)` : ''}`,
    description: (describeAdvisories(vulns) || 'Known vulnerability in this dependency version.').slice(0, 2000),
    file: dep.file,
    line: dep.line,
    lineEnd: dep.line,
    ruleId: dep.name,
    confidence: 'high',
  };
}

function runScan(rootDir, onProgress) {
  const emit = (message) => { if (onProgress) onProgress(message); };

  return new Promise((resolve) => {
    if (!isApplicable(rootDir)) {
      emit('OSV dependency scan skipped — no requirements.txt/go.mod/Cargo.lock in this folder');
      resolve({ findings: [] });
      return;
    }

    const deps = collectDependencies(rootDir);
    if (deps.length === 0) {
      emit('OSV dependency scan: manifest found but no pinned versions to check');
      resolve({ findings: [] });
      return;
    }

    emit(`querying OSV.dev for ${deps.length} pinned dependency version(s)`);

    const timeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('exceeded the time budget')), OVERALL_TIMEOUT_MS);
    });

    // Network-dependent and best-effort by nature -- a failure here (OSV
    // down, offline, etc.) shouldn't take the whole scan down with it, so
    // this always resolves rather than rejecting.
    Promise.race([queryAll(deps, emit), timeout])
      .then((results) => {
        const findings = results.map(({ dep, vulns }) => toFinding(dep, vulns));
        emit(`OSV scan finished: ${findings.length} finding(s)`);
        resolve({ findings });
      })
      .catch((err) => {
        emit(`OSV scan failed (${err.message}) -- continuing without it`);
        resolve({ findings: [] });
      });
  });
}

module.exports = { isApplicable, runScan };
