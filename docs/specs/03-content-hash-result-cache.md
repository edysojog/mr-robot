# Spec 03: Content-Hash Result Cache for the AI Pass

Status: draft · Independent of Specs 01/02 (composes with both)

## Problem

Every scan pays full price for identical work. Rerunning on a repo where 5% of files changed re-reviews the other 95% at temperature 0.3 (`auditorShared.js:11`), producing different findings each time — which is why the project's own README bans the AI pass from CI gates ("costs money per run and output varies"). Both objections die if verdicts are content-addressed and replayed.

## Design

### 1. Cache key = everything that affects the response

```js
key = sha256(JSON.stringify({
  pipelineVersion,        // bump when prompts/schemas/logic change -> mass invalidation
  provider, model,
  stage,                  // 'recon' | 'scanner' | 'verifier:<specialist?>'
  temperature, maxTokens,
  systemPromptHash,       // sha1 of the exact system prompt string
  userContentHash,        // sha1 of the exact user message
}))
```

Because `buildBatchUserContent()` already folds in the recon summary and semgrep context, those inputs are automatically part of the key — no special casing. One subtlety: recon itself varies run-to-run and would poison downstream keys, so **recon responses are cached too**, keyed by `fileListHash + seedFileContentsHash` (`buildReconUserContent` output). Unchanged repo → identical recon → identical scanner keys.

### 2. Integration point

Each auditor's API call sites route through a shared helper instead of hitting the SDK directly:

```js
const completion = await cacheWrap(
  { stage: 'scanner', temperature, maxTokens, system, userContent },
  () => this.client.chat.completions.create({...})
);
```

`cacheWrap` returns `{result, cacheHit}`; auditors thread a `cacheHits/calls` tally into the existing progress emits and the final `review()` return (`{findings, batchCount, partial, cacheStats}`). `MockAuditor` ignores the cache. Verifier calls cache identically — and **error paths never cache**: the fail-open branch at `groqAuditor.js:220-222` keeps reporting unverified candidates live; a transient outage must not fossilize degraded output.

### 3. Storage backends

Same split as Spec 01's history:

| Backend | Path | Notes |
| --- | --- | --- |
| Desktop | `userData/cache.json` | Optional follow-up: encrypt at rest via `safeStorage` like `secureStore` (code snippets are sensitive-at-rest). |
| CLI/CI | `<repo>/.mrrobotbot/cache.json` | Default gitignored. Committing it is supported for team-shared warm CI caches — size-managed, see eviction. |

Entry shape: `{ key, stage, response, createdAt, lastHitAt, hits, bytes }`. Reads tolerate corruption (parse failure → treat as empty, never throw). Writes atomic (tmp + rename) and debounced — flush once at end of `review()`, not per call.

### 4. Eviction & limits

LRU by `lastHitAt`, hard caps: 50MB total / 90 days. Enforced on flush. `mrrobot cache stats|prune|clear` subcommands; desktop Settings gets the same three buttons.

### 5. Determinism policy (explicit, not hand-wavy)

Cache hits replay verbatim, so repeat scans converge to frozen output regardless of temperature. Cross-machine determinism (fresh clone + warm cache = identical report) additionally requires generation-time determinism: introduce `--reproducible`, which sets temperature 0 for the run and refuses recon (fixed ordering: `prioritizeFiles` input list). Document that normal-mode first runs remain probabilistic; the cache freezes whatever they produce.

### 6. Interactions with existing mechanics

- `MAX_BATCHES=15` slice and `estimateTotalBatches` operate on file texts, not API calls — unchanged; cached batches still count toward the cap so `partial` stays truthful.
- `prioritizeFiles` depends on semgrep findings, which are deterministic locally — good for key stability. Recon priority files feed it, hence caching recon first matters.
- Cost math lands in the terminal report: `AI pass: 38 calls (34 cached, $0.00 est · 4 fresh)`.

## Rollout & tests

Flags: `--no-cache` (default ON for cache; opt-out only), `--reproducible`. Announce the CI reversal in the README: with a committed/restored cache, AI-in-CI becomes affordable and stable — update the "keep AI out of CI" guidance accordingly.

Tests: key-stability fixtures (same inputs → same key across processes); hit/miss accounting with the mock provider; corrupt-file recovery; eviction boundary; verifier-error-not-cached regression; end-to-end temp-repo test asserting second scan makes zero fresh calls after touching one file (and that only that file's batches refetch).
