const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const LINE_PROXIMITY = 3;

function higherSeverity(a, b) {
  return SEVERITY_RANK[a] <= SEVERITY_RANK[b] ? a : b;
}

// LLM-reported file paths don't always match Semgrep's byte-for-byte (e.g.
// a leading "./", backslashes, or case differences on Windows), so compare
// normalized paths rather than raw strings.
function normalizeFilePath(file) {
  return file
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .toLowerCase();
}

function isDuplicate(a, b) {
  if (normalizeFilePath(a.file) !== normalizeFilePath(b.file)) return false;
  return Math.abs(a.line - b.line) <= LINE_PROXIMITY;
}

// Merges static-tool + AI findings: same file with a nearby line is treated
// as one finding regardless of source. `staticFindings` is every static
// pass combined (Semgrep, Gitleaks, npm audit) -- a match against any of
// them counts as a cross-tool confirmation, not just Semgrep. AI's
// description wins (richer rationale); the static finding's ruleId is kept
// for traceability; severity escalates to the higher of the two.
// `staticSource` records which specific static tool actually matched, so
// the UI can say e.g. "confirmed by gitleaks + ai" instead of a generic
// "both" that reads as semgrep-only.
function merge(staticFindings, claudeFindings) {
  const merged = [];
  const claudeUsed = new Set();

  staticFindings.forEach((sf) => {
    const match = claudeFindings.find((cf) => !claudeUsed.has(cf.id) && isDuplicate(sf, cf));
    if (match) {
      claudeUsed.add(match.id);
      merged.push({
        ...sf,
        source: 'both',
        staticSource: sf.source,
        severity: higherSeverity(sf.severity, match.severity),
        description: match.description || sf.description,
        confidence: match.confidence || sf.confidence,
        mergedFrom: [sf.id, match.id],
      });
    } else {
      merged.push(sf);
    }
  });

  claudeFindings.forEach((cf) => {
    if (!claudeUsed.has(cf.id)) merged.push(cf);
  });

  return rank(merged);
}

function rank(findings) {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (sevDiff !== 0) return sevDiff;

    const bothA = a.source === 'both' ? 0 : 1;
    const bothB = b.source === 'both' ? 0 : 1;
    if (bothA !== bothB) return bothA - bothB;

    return a.file.localeCompare(b.file);
  });
}

module.exports = { merge };
