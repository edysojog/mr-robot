# Spec 01: Finding-Level Scan Delta (new / fixed / unchanged)

Status: draft · Depends on: Spec 02 (identity function) · Enables: PR gating, burndown charts, `--fail-on-new`

## Problem

`scanHistoryStore.recordScan()` stores only aggregate counts per scan (`scanHistoryStore.js:45-53`). The desktop app fetches `previousScan` and shows a "comparison" (`scanHandlers.js:165,177`), but with counts alone it cannot say *which* findings appeared, disappeared, or persisted. The README oversells this ("the next one can show you what changed"). Meanwhile the raw material exists: `baselineStore.fingerprint()` proves stable-ish keys are feasible — it just needs Spec 02's identity to become trustworthy.

## Design

### 1. History entries carry identities

`recordScan()` additionally stores a compact map, capped at ~2000 entries to bound file growth (largest scans today hit the batch cap long before that):

```js
{
  ...existingFields,
  identities: { [identity]: { severity, title, file } },
}
```

No descriptions/snippets — the full findings live in the current scan; history only needs enough to label a delta row.

### 2. New module `src/main/services/scanDelta.js`

```js
diffScans(previousEntry, currentFindings) ->
  { skipped?: 'scope-mismatch' | 'no-previous' | 'legacy-entry',
    added:   [{...finding}], removed: [{...previousMeta}], unchangedCount }
```

Rules:

- `added` = identities present now, absent before. `removed` ("fixed") = inverse.
- **Scope guard:** comparing a full scan against a `diffMode` scan floods the user with fake "fixed" rows (only changed files were looked at). If `previousEntry.diffMode !== currentDiffMode`, skip and report why.
- Legacy entries without `identities` → `skipped: 'legacy-entry'`, never crash.
- First-ever scan → `skipped: 'no-previous'`.

`summary.delta = { addedCount, removedCount, unchangedCount, addedBySeverity, skipped? }` computed in `scanHandlers.js` *before* `recordScan` (today's code grabs `previousScan` first — order already correct).

### 3. Storage backends (fixes the CLI gap)

Extract a tiny interface: `getHistory(rootDir) / recordScan(...)` with two implementations:

| Backend | Location | Used by |
| --- | --- | --- |
| `electronHistoryStore` | `userData/scanHistory.json` (unchanged) | Desktop app |
| `projectHistoryStore` | `<repo>/.mrrobotbot/history.json` | CLI, chat agent, CI |

Project-local history makes deltas work headlessly and lets teams commit it if they want CI deltas (suggest gitignoring by default; ~KB-scale). CLI gains `--no-history`; default on. The pre-commit hook inherits this for free.

### 4. Surfaces

- **Terminal report**: header line gains `· 3 new, 5 fixed since last scan`; new findings get a `NEW` marker in their listing.
- **JSON/markdown/html**: `delta` block in the model; markdown renders Added/Fixed sections.
- **Desktop results screen**: badge chips (`3 NEW` / `5 FIXED`) + filter tabs All/New/Known; clicking a "fixed" chip can show what closed (from history meta).
- **Chat agent**: once `toolScanProject` routes through the shared pipeline (see drift note below), deltas appear in scan summaries automatically.

### 5. The payoff flag: `--fail-on-new <severity>`

Independent exit trigger: exit 1 only if an **added** finding meets the threshold. This is the gate teams actually want — legacy debt stops blocking every PR while regressions stay fatal. Semantics: if both `--fail-on` and `--fail-on-new` are set, either tripping exits 1; `--fail-on-new` implies history recording even with `--no-history`.

CI caveat, stated honestly: ephemeral runners have no history unless it's committed or restored via actions/cache. Document the restore pattern in the README's CI section alongside the existing guidance.

## Out of scope (follow-ups)

Burndown/MTTR charts in the desktop app (needs ≥N scans of data + chart lib decision); cross-repo dashboards; auto-baselining of `removed` findings.

## Tests

`scanDelta` unit suite: added/removed/unchanged basics, scope-mismatch, legacy entry, empty repo, identity collision from Spec 02's ordinal shift (asserts honest false-pair rather than crash). Store round-trips for both backends. CLI integration test in a temp git repo: seed scan → fix one finding, add another → assert exit codes for `--fail-on high` vs `--fail-on-new high` diverge correctly.
