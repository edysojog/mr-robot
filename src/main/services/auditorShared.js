const fs = require('fs');
const crypto = require('crypto');
const { MAX_FILE_BYTES_FOR_LLM, MAX_TOTAL_LLM_BYTES } = require('../constants/excludes');

const TOKENS_PER_BATCH_TARGET = 50000;
const MAX_BATCHES = 15;

// Low but non-zero: cuts run-to-run variance in which findings get
// reported, while still leaving room for the model to flag less-obvious,
// lower-confidence leads instead of only the safest/most textbook issues.
const AUDITOR_TEMPERATURE = 0.3;

const REPORT_FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          title: { type: 'string' },
          description: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          lineEnd: { type: 'integer' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['severity', 'title', 'description', 'file', 'line', 'confidence'],
      },
    },
  },
  required: ['findings'],
};

function makeId(source, parts) {
  return crypto.createHash('sha1').update([source, ...parts].join('|')).digest('hex').slice(0, 16);
}

function readFileForPrompt(file) {
  const content = fs.readFileSync(file.absolutePath, 'utf8');
  const numbered = content
    .split('\n')
    .map((line, i) => `${i + 1}| ${line}`)
    .join('\n');
  return `--- FILE: ${file.relativePath} ---\n${numbered}\n`;
}

// Picks which files to send: Semgrep-flagged files first (full priority),
// then a breadth sample of the rest, capped by MAX_TOTAL_LLM_BYTES.
function prioritizeFiles(files, semgrepFindings) {
  const flaggedPaths = new Set(semgrepFindings.map((f) => f.file));
  const flagged = files.filter((f) => flaggedPaths.has(f.relativePath));
  const rest = files.filter((f) => !flaggedPaths.has(f.relativePath));

  const ordered = [...flagged, ...rest];
  const selected = [];
  let totalBytes = 0;

  for (const file of ordered) {
    if (file.size > MAX_FILE_BYTES_FOR_LLM) continue;
    if (totalBytes + file.size > MAX_TOTAL_LLM_BYTES) continue;
    selected.push(file);
    totalBytes += file.size;
  }

  return selected;
}

// Batches by a char/4 token estimate rather than an exact token count --
// the target is a soft budget, not a hard limit, so the estimate is
// good enough and avoids an extra API round-trip per file. tokensPerBatch
// is overridable per-provider: Claude's paid tier has generous rate limits,
// but Groq's free tier caps at 12k tokens/minute *per request* -- a batch
// sized for Claude's default blows straight through that and 413s.
function batchByTokens(fileTexts, tokensPerBatch = TOKENS_PER_BATCH_TARGET) {
  const batches = [];
  let current = [];
  let currentTokens = 0;

  for (const entry of fileTexts) {
    const estimate = Math.ceil(entry.text.length / 4);
    if (current.length > 0 && currentTokens + estimate > tokensPerBatch) {
      batches.push(current);
      current = [];
      currentTokens = 0;
    }
    current.push(entry);
    currentTokens += estimate;
  }
  if (current.length > 0) batches.push(current);

  return batches.slice(0, MAX_BATCHES);
}

function estimateTotalBatches(fileTexts, tokensPerBatch = TOKENS_PER_BATCH_TARGET) {
  let totalTokens = 0;
  for (const entry of fileTexts) totalTokens += Math.ceil(entry.text.length / 4);
  return Math.ceil(totalTokens / tokensPerBatch) || 1;
}

function buildBatchUserContent(batch, semgrepFindings, reconSummary) {
  const batchPaths = new Set(batch.map((b) => b.file.relativePath));
  const relevantSemgrep = semgrepFindings.filter((f) => batchPaths.has(f.file));

  const semgrepContext = relevantSemgrep.length
    ? `Semgrep already flagged the following in this batch:\n${relevantSemgrep
        .map((f) => `- ${f.file}:${f.line} [${f.severity}] ${f.ruleId}: ${f.description}`)
        .join('\n')}`
    : 'Semgrep did not flag anything in this batch.';

  const reconContext = reconSummary ? `Recon summary of the overall codebase:\n${reconSummary}\n\n` : '';

  return `${reconContext}${semgrepContext}\n\n${batch.map((b) => b.text).join('\n')}`;
}

const RECON_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string', description: '3-6 sentence overview of what this codebase does, its trust boundaries, and its highest-risk surface.' },
    priorityFiles: {
      type: 'array',
      items: { type: 'string' },
      description: 'Relative file paths (from the list given) most worth a close read, ordered by priority.',
    },
  },
  required: ['summary', 'priorityFiles'],
};

const RECON_FILE_LIST_CAP = 500;
const ENTRY_POINT_NAME_RE = /^(server|app|main|index)$/i;

// Files worth reading in full for recon, on top of the bare file list --
// capped small since this is a single call sent once per scan, not
// something worth spending the whole token budget on.
function pickReconSeedFiles(files) {
  const seeds = files.filter((f) => {
    const base = f.relativePath.split('/').pop();
    const nameNoExt = base.replace(/\.[^.]+$/, '');
    return ENTRY_POINT_NAME_RE.test(nameNoExt) || base.toLowerCase() === 'package.json';
  });
  return seeds.slice(0, 6);
}

function buildReconUserContent(files) {
  const truncated = files.length > RECON_FILE_LIST_CAP;
  const fileList = files.slice(0, RECON_FILE_LIST_CAP).map((f) => f.relativePath).join('\n');
  const seeds = pickReconSeedFiles(files);
  const seedText = seeds.map((f) => readFileForPrompt(f)).join('\n');

  return [
    `Full file list (${files.length} files${truncated ? `, showing first ${RECON_FILE_LIST_CAP}` : ''}):`,
    fileList,
    '',
    seedText ? `Contents of likely entry points:\n${seedText}` : 'No obvious entry-point files (server/app/main/index/package.json) were found in the list.',
  ].join('\n');
}

// Folds the recon stage's priority files into the same shape prioritizeFiles()
// already reads from semgrepFindings (just a .file property) so recon-flagged
// files get the same token-budget priority as static-tool-flagged ones,
// without prioritizeFiles needing to know recon exists.
function reconPriorityAsFindings(priorityFiles) {
  return (priorityFiles || []).map((file) => ({ file }));
}

const VERIFY_FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          index: { type: 'integer', description: 'Position of the candidate finding in the list you were given, starting at 0.' },
          verdict: { type: 'string', enum: ['confirm', 'reject'] },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'], description: 'Only include to downgrade the scanner\'s severity.' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'], description: 'Only include to downgrade the scanner\'s confidence.' },
          reason: { type: 'string' },
        },
        required: ['index', 'verdict', 'reason'],
      },
    },
  },
  required: ['verdicts'],
};

function buildVerificationUserContent(batch, candidateFindings) {
  const list = candidateFindings
    .map((f, i) => `${i}. [${f.severity}/${f.confidence || 'unknown'}] ${f.file}:${f.line} "${f.title}" -- ${f.description}`)
    .join('\n');

  return `Candidate findings from the scanner stage, to verify against the source below:\n${list}\n\n${batch.map((b) => b.text).join('\n')}`;
}

// Applies verifier verdicts to the scanner's draft findings: rejected
// findings are dropped, confirmed ones keep their id (so baseline
// suppression / history still track the same fingerprint) but may have
// severity/confidence downgraded, and pick up verified:true plus the
// verifier's reason appended for audit-trail transparency in the UI/report.
function applyVerdicts(candidateFindings, verdicts) {
  const byIndex = new Map((verdicts || []).map((v) => [v.index, v]));

  return candidateFindings
    .map((finding, i) => {
      const verdict = byIndex.get(i);
      // No verdict returned for this index (model omitted it) -- fail safe
      // by dropping it rather than reporting an unverified finding.
      if (!verdict || verdict.verdict !== 'confirm') return null;

      return {
        ...finding,
        severity: verdict.severity || finding.severity,
        confidence: verdict.confidence || finding.confidence,
        verified: true,
        verifierReason: verdict.reason,
      };
    })
    .filter(Boolean);
}

const SPECIALIST_SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SPECIALIST_LINE_PROXIMITY = 3;

function normalizeSpecialistPath(file) {
  return (file || '').trim().replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
}

// Merges candidate-finding arrays from multiple specialist scanner calls run
// in parallel over the same batch. Specialists are prompted to stay in their
// own lane, but overlap still happens (e.g. an auth-bypass-via-injection bug
// both the authz and injection specialists notice) -- same file + nearby
// line is treated as one finding, keeping the higher severity and the
// specialist tag(s) that flagged it, so the verifier sees one candidate
// instead of near-duplicates.
function mergeSpecialistCandidates(candidateArrays) {
  const merged = [];

  for (const candidates of candidateArrays) {
    for (const candidate of candidates) {
      const existing = merged.find(
        (m) =>
          normalizeSpecialistPath(m.file) === normalizeSpecialistPath(candidate.file) &&
          Math.abs(m.line - candidate.line) <= SPECIALIST_LINE_PROXIMITY
      );

      if (!existing) {
        merged.push({ ...candidate, specialists: [candidate.specialist].filter(Boolean) });
        continue;
      }

      existing.specialists.push(candidate.specialist);
      if (SPECIALIST_SEVERITY_RANK[candidate.severity] < SPECIALIST_SEVERITY_RANK[existing.severity]) {
        existing.severity = candidate.severity;
        existing.title = candidate.title;
        existing.description = candidate.description;
      }
    }
  }

  return merged;
}

function toFinding(source, f) {
  return {
    id: makeId(source, [f.file, String(f.line), f.title]),
    source,
    severity: f.severity,
    title: f.title,
    description: f.description,
    file: f.file,
    line: f.line,
    lineEnd: f.lineEnd || f.line,
    confidence: f.confidence,
  };
}

module.exports = {
  AUDITOR_TEMPERATURE,
  REPORT_FINDINGS_SCHEMA,
  VERIFY_FINDINGS_SCHEMA,
  RECON_SCHEMA,
  readFileForPrompt,
  prioritizeFiles,
  batchByTokens,
  estimateTotalBatches,
  buildBatchUserContent,
  buildVerificationUserContent,
  buildReconUserContent,
  reconPriorityAsFindings,
  applyVerdicts,
  mergeSpecialistCandidates,
  toFinding,
};
