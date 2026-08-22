# Spec 02: CWE-Stable Identity for AI Findings

Status: draft · Priority: do first (Specs 01 and 03 depend on its identity function)

## Problem

Three separate mechanisms key off unstable AI-finding attributes today:

| Mechanism | Key today (`baselineStore.js:14`, `reportExporter.js:150`) | Failure mode |
| --- | --- | --- |
| Baseline suppression fingerprint | `sha1(file :: ruleId\|\|title :: severity)` | Scanner words the title differently next run (temp is 0.3) → suppression silently misses → finding resurrects. Verifier **downgrades severity** → severity part of hash changes → same resurrection. |
| SARIF rule IDs | `ruleId \|\| slugify(title)` | Reworded titles create "new" rules in GitHub code scanning → alert churn every run. |
| History deltas (planned, Spec 01) | n/a yet | Needs a stable key that survives line drift AND wording drift, or every rescan reads as all-new findings. |

Meanwhile the pipeline throws away the one stable identifier it already asks the model about: `SCANNER_SYSTEM_PROMPT` embeds `CWE_REFERENCE` (`src/main/constants/systemPrompt.js:24`) but `REPORT_FINDINGS_SCHEMA` (`auditorShared.js:13`) has no `cwe` field, so `toFinding()` drops it. Semgrep findings, by contrast, already carry `cwe`/`owasp` arrays extracted from rule metadata (`semgrepRunner.js:82`).

## Goal

One canonical identity function used by baseline suppression, scan-history deltas, and SARIF export. For AI findings it keys on CWE instead of free-text title; severity is excluded everywhere so verifier downgrades stop breaking suppressions.

## Design

### 1. New shared module `src/main/services/findingIdentity.js`

```js
// ruleKey precedence: explicit rule > CWE class > slugified title.
// instanceIndex disambiguates multiple hits of the SAME rule in ONE file:
// sort that file's same-ruleKey findings by (line, title) and use the
// 1-based ordinal. Without it, two SQL injections in db.js collide into
// one identity; with it, identities survive edits above the finding
// (line numbers move, relative order rarely does).
function ruleKey(finding) {
  if (finding.ruleId) return finding.ruleId.trim().toLowerCase();
  const cwe = firstCwe(finding);            // 'CWE-89' or null
  if (cwe) return cwe.toLowerCase();
  return slugify(finding.title);
}

function identity(finding, sameGroupOrdinal) {
  return sha1(`${normFile(finding.file)}::${ruleKey(finding)}::${sameGroupOrdinal}`).slice(0, 16);
}
```

`assignIdentities(findings)` groups by `normFile::ruleKey`, sorts each group by `(line, title)`, stamps `finding.identity`. Called once per scan right before merge/baseline filtering.

Known limitation (documented, accepted for v1): fixing one of two same-rule findings in a file shifts the ordinal of the other → one false fixed+new pair. v2 option: fold a short hash of the flagged source lines into the identity (Semgrep provides matched text in `extra.lines`; AI findings would need to start quoting code). Ship v1 simple.

Severity is deliberately NOT part of the identity. Tradeoff: suppressing an `info` also suppresses a future `critical` on the same spot. Accepted — the old behavior (downgrade silently un-suppresses) is strictly worse; the baseline UI shows stored vs current severity so drift stays visible.

### 2. Schema + sanitization (`auditorShared.js`)

Add to `REPORT_FINDINGS_SCHEMA.items.properties`:

```json
"cwe": { "type": "string", "pattern": "^CWE-[0-9]+$" }
```

Single primary CWE, not a list — lists make identity ambiguous. Models ignore patterns often, so sanitize in `toFinding()`:

```js
const m = /CWE-(\d+)/.exec(String(f.cwe || ''));
cwe: m ? [`CWE-${m[1]}`] : undefined,
```

Static findings keep their existing `cwe` arrays; canonical element is `[0]` everywhere (`firstCwe()` helper). Normalize semgrep's occasionally messy metadata strings through the same regex.

### 3. Prompt updates (`systemPrompt.js`)

- Scanner: "Tag every finding with its primary CWE id from the reference above. If genuinely none applies, omit it."
- Verifier (`VERIFY_FINDINGS_SCHEMA.verdicts.items`): add optional `"cwe"` with description *"Only include to correct a mislabeled candidate."* `applyVerdicts` copies it like a severity override. Safe for stability because identities are assigned **after** verification, before merge/baseline/history.

### 4. Consumers switched over

- `baselineStore.fingerprint()` delegates to `findingIdentity` (keeps its public name; callers unchanged).
- `reportExporter.toSarif()`: when `firstCwe(f)` exists, ruleId becomes `mrrobotbot/${cwe}-${slugify(title)}` — stable prefix kills alert churn, human-readable suffix survives. Add `tags: ['security', f.source, cwe, ...owasp]`.
- Terminal/markdown/html reports print the CWE tag (markdown/html renderers already check `f.cwe` conditionally at `reportExporter.js:63` — they'll just start receiving it).

### 5. Baseline migration

Old fingerprints differ from new ones → every previously suppressed finding resurfaces exactly once. Mitigate with `mrrobot baseline migrate` (and a Settings button in the app): `addSuppression` already persists `title/file/severity/ruleId` per entry (`baselineStore.js:42`), which is enough to recompute both old and new fingerprints and rewrite the file in place. Entries that can't be rematched are kept untouched and reported.

## Rollout & tests

- No new flags; behavior change ships behind nothing (suppression re-surfacing is handled by migrate). Call it out in CHANGELOG.
- Unit tests: `findingIdentity` grouping/ordering/tie-breaks; sanitizer against `'cwe: 89'`, `'CWE-79 XSS'`, `'banana'`; verifier cwe correction passthrough; SARIF snapshot before/after; migration round-trip on the repo's own committed baseline.
- Acceptance: suppress an AI finding → rerun twice → still suppressed with a differently-worded title and a verifier downgrade; SARIF diff between two runs shows zero rule-ID churn on unchanged findings.
