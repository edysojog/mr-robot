const fs = require('fs');
const path = require('path');

const GUIDES_DIR = path.join(__dirname, '..', 'knowledge', 'remediation');

// Mirrors the CWE groupings in constants/cweReference.js, so a guide exists
// for every category the scanner/verifier are told to look for.
const CWE_TO_GUIDE = {
  'CWE-89': 'sql-injection.md',
  'CWE-78': 'command-injection.md',
  'CWE-79': 'xss.md',
  'CWE-94': 'code-injection.md',
  'CWE-798': 'hardcoded-secrets.md',
  'CWE-321': 'hardcoded-secrets.md',
  'CWE-306': 'missing-authentication.md',
  'CWE-862': 'broken-authorization.md',
  'CWE-863': 'broken-authorization.md',
  'CWE-352': 'csrf.md',
  'CWE-502': 'insecure-deserialization.md',
  'CWE-611': 'xxe.md',
  'CWE-918': 'ssrf.md',
  'CWE-295': 'certificate-validation.md',
  'CWE-326': 'weak-crypto.md',
  'CWE-327': 'weak-crypto.md',
  'CWE-732': 'permission-assignment.md',
  'CWE-639': 'idor.md',
  'CWE-522': 'credential-exposure.md',
};

// Fallback for findings with no cwe tag (npm-audit, or an AI-sourced
// finding that never set one) -- matched against title+description text.
const KEYWORD_TO_GUIDE = [
  [/sql injection/i, 'sql-injection.md'],
  [/command injection|shell injection|os command/i, 'command-injection.md'],
  [/cross[- ]site scripting|\bxss\b/i, 'xss.md'],
  [/code injection|template injection/i, 'code-injection.md'],
  [/hardcoded (credential|secret|key|password|api key)/i, 'hardcoded-secrets.md'],
  [/missing authentication/i, 'missing-authentication.md'],
  [/(broken|missing|incorrect) authoriz/i, 'broken-authorization.md'],
  [/cross[- ]site request forgery|\bcsrf\b/i, 'csrf.md'],
  [/insecure deserialization/i, 'insecure-deserialization.md'],
  [/xml external entity|\bxxe\b/i, 'xxe.md'],
  [/server[- ]side request forgery|\bssrf\b/i, 'ssrf.md'],
  [/certificate validation|reject[- ]?unauthorized/i, 'certificate-validation.md'],
  [/weak (crypto|hash|cipher)|broken cryptography|ecb mode/i, 'weak-crypto.md'],
  [/permission assignment|world[- ]?writable|overly permissive/i, 'permission-assignment.md'],
  [/insecure direct object reference|\bidor\b/i, 'idor.md'],
  [/plaintext (password|credential|token)/i, 'credential-exposure.md'],
];

const guideCache = new Map();

function readGuide(filename) {
  if (guideCache.has(filename)) return guideCache.get(filename);
  let content;
  try {
    content = fs.readFileSync(path.join(GUIDES_DIR, filename), 'utf8').trim();
  } catch {
    content = null;
  }
  guideCache.set(filename, content);
  return content;
}

function guideFilenameForFinding(finding) {
  const cweList = Array.isArray(finding.cwe) ? finding.cwe : [];
  for (const cwe of cweList) {
    const match = /CWE-\d+/i.exec(cwe);
    const id = match && match[0].toUpperCase();
    if (id && CWE_TO_GUIDE[id]) return CWE_TO_GUIDE[id];
  }
  const text = `${finding.title || ''} ${finding.description || ''}`;
  const hit = KEYWORD_TO_GUIDE.find(([pattern]) => pattern.test(text));
  return hit ? hit[1] : null;
}

// Returns the matching remediation reference (trimmed markdown) for a
// finding, or null if no CWE/keyword match was found.
function getRemediationGuide(finding) {
  const filename = guideFilenameForFinding(finding);
  return filename ? readGuide(filename) : null;
}

module.exports = { getRemediationGuide };
