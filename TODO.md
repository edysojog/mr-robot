# MrRobotBot — To-Do

## Fixes
- [x] Disable "Start Scan" button while a scan is in progress (currently a double-click fires two concurrent scans)
- [x] Mock/dry-run mode for the Claude pass — canned findings instead of a real API call, so the merge/dedupe/UI can be tested for free
- [ ] Re-verify the real Claude pass end-to-end once Anthropic billing credits are added (untested so far — last run failed on "credit balance too low")
- [x] Add a free LLM provider option (Groq) so the AI pass can be tested for real without spending Claude API credits — provider dropdown in Settings (mock/groq/claude), each with its own stored key
- [x] Fixed: Semgrep findings used absolute file paths while the LLM pass used paths relative to the scanned folder, so overlapping findings never merged into "confirmed by both" — normalized both to rootDir-relative paths
- [x] Lowered LLM temperature (0.3) on both Claude and Groq calls to reduce run-to-run variance in which findings get reported

## Phase 4 — polish + packaging
- [x] Results screen: filter/sort/search
- [x] Results screen: click-to-open-file in editor
- [x] Report export: Markdown / HTML / JSON with save dialog (built — formatting needs a pass, revisit later)
- [x] Settings: model picker (Sonnet vs Opus)
- [x] Settings: "test key" button (cheap validation call — note: this one does cost a tiny amount, unlike mock mode)
- [x] Settings: recent-folders list
- [x] Package with electron-builder into a Windows .exe/installer
- [x] Verify the packaged build works end-to-end, not just `electron .` dev mode

- [x] **Diff-mode scan** — checkbox on the folder screen (enabled only for git repos) to scan only files changed since the last commit (staged + unstaged + untracked, not deletions) instead of the whole repo. Scopes both Semgrep and the AI pass to just those files.

- [x] **Headless/CLI mode** — `src/cli/index.js` (`npm run scan -- <folder> [options]`), no Electron dependency, reuses the same scan services as the GUI (Semgrep, Claude/Groq/mock passes, merge, baseline suppression, diff mode, JSON/Markdown/HTML export). Exit code 1 if any finding is at/above `--fail-on` severity (default `high`) — CI-gateable. API key via `--api-key` or `ANTHROPIC_API_KEY`/`GROQ_API_KEY` env vars (no secureStore/Electron userData involved). This is the prerequisite SARIF export and a pre-commit hook both need.

- [x] **Pre-commit hook** — "install pre-commit hook" button on the folder screen (git repos only). Writes `.git/hooks/pre-commit` running the CLI in `--diff --semgrep-only --fail-on high` mode via Electron's bundled Node (`ELECTRON_RUN_AS_NODE=1`, no separate Node.js install needed). Blocks a commit if it introduces a new high/critical Semgrep finding; never clobbers a pre-existing (e.g. Husky) hook; uninstall only removes hooks it installed. Verified blocking a real commit, then letting it through once fixed.

## Differentiator ideas (make it stand out vs. a one-off AI code review)
- [x] **Baseline / triage memory** — mark a finding "not a bug" once, stored per-project in `.mrrobotbot-baseline.json` (committable, shareable across a team), suppressed on all future scans, with a "manage suppressed" panel to restore.
- [x] **Scan history + trend tracking** — every real scan is recorded centrally (keyed by project path, capped at 50/project), results screen shows a "vs last scan" delta and a "view history" panel listing past scans with date + severity breakdown
- [x] **SARIF export** — standard format GitHub/GitLab code-scanning ingests (`--format sarif` in the CLI, "export .sarif" in the GUI), so this can gate PRs in CI instead of being a manual-only tool
- [x] **Explicit privacy/offline positioning** — static note on the folder screen and next to the provider picker in Settings: nothing leaves the machine except file contents sent to the selected AI provider during the AI pass; static tools never make network calls; mock mode is fully offline
- [ ] **Dependency-aware context** — largely covered by npm audit now (CVEs from package.json); still open: cross-referencing via OSV directly for ecosystems npm audit doesn't cover (requirements.txt, go.mod, etc.)
- [ ] **Watch mode** — lightweight file-watcher that incrementally re-scans changed files on save, closer to a linter than a one-shot run

## Backend architecture (DeepAudit-inspired, scoped to stay infra-free)
- [x] **Broader static tool suite** — Gitleaks (secrets) + npm audit (deps) alongside Semgrep, each independently toggleable via the folder-screen checklist
- [x] **Scanner → Verifier pass** — AI findings get a second, adversarial LLM call before reporting (confirm/reject/downgrade), with role-scoped system prompts and a Settings toggle
- [x] **Recon pass** — one upfront LLM call per scan to map the codebase's attack surface and prioritize which files the scanner reads closely
- [x] **CWE/OWASP grounding** — static reference of ~16 vulnerability classes baked into the scanner prompt (the RAG-lite alternative to a vector DB)
- [x] **Fix Groq batch-size vs rate-limit mismatch** — `batchByTokens`/`estimateTotalBatches` now take an optional per-provider token target; Groq uses 5k/batch + 2k max output (vs Claude's 50k default) to stay under its 12k TPM per-request cap. Note: this fixes the per-request 413, not cumulative TPM throttling across recon+scanner+verifier calls landing in the same minute on a fast scan — a real 429 is still possible on a large scan and would need request queuing/backoff to fully close.
- [x] **Pin safety-net Semgrep rule IDs** — added a `SAFETY_NET_RULE_IDS` list in `semgrepRunner.js`, currently pinning the one verified gap (`python.lang.security.audit.dangerous-system-call-audit`, confirmed missing from `p/security-audit`/`p/python` but fires standalone). Mechanism is there for more as they're found — only add an ID after actually verifying it's both real and missing from the packs, not by guessing.
- [ ] Deliberately still out of scope: Docker sandbox, PoC/exploit generation, Postgres/vector DB — conflicts with the "read-only, no-infra auditor" positioning unless that's a deliberate future pivot

## Phase 5 — frontend redesign
- [ ] **New visual design pass** — current UI is a functional terminal-styled shell; revisit layout/IA now that the feature set (checklist, verification, recon, SARIF, history, baseline) has grown well past the original screens
- [x] **Onboarding flow replacing the Settings tab** — the "settings" screen itself was restructured, not replaced with a separate screen: on first launch (`localSettings.getSetupComplete()` false), `main.js` routes straight to it with a welcome blurb instead of the folder picker, and the back button reads "Continue →" instead of "← Back". Provider selection changed from an always-visible 6-panel stack to a **choose-your-provider-first** flow — six cards (mock/groq/claude/gemini/openai/ollama), and only the selected one's key/model panel is shown; the rest stay hidden until picked. Tool-install status (Semgrep/Gitleaks/npm) moved into this same screen so setup and tool-check happen in one place. Settings is still reachable anytime via the same "settings" button — nothing was removed, `setupComplete` just gates whether it's also the first thing you see.
- [ ] **Chat-style explanation of findings** — let the user ask follow-up questions about a specific finding ("why is this exploitable", "what would fix this") instead of just reading the static description; scoped to explain/discuss only, consistent with the "report only, never auto-fix" rule
- [x] **More LLM providers** — Gemini, OpenAI, and local Ollama alongside Claude/Groq/mock (`geminiAuditor.js`/`openaiAuditor.js`/`ollamaAuditor.js`, same Recon→Scanner→Verifier interface). Model selection is now a free-text per-provider override (`localSettings.getProviderModel`/`setProviderModel`) instead of a fixed enum — Gemini/OpenAI/Ollama model catalogs change too often, and Ollama's valid set is whatever's locally pulled, to safely hardcode a restricted list like Claude's old dropdown had. Ollama needs no API key (local, `KEYLESS_PROVIDERS`) but does need a base URL (default `http://localhost:11434/v1`, overridable). CLI: `--provider gemini|openai|ollama`, `GEMINI_API_KEY`/`OPENAI_API_KEY` env vars, `--ollama-url`/`OLLAMA_BASE_URL`. Not yet real-key-tested against live Gemini/OpenAI/Ollama endpoints — only verified via instantiation, mock-provider regression, and CLI error-path checks (missing-key exit code, `--semgrep-only` bypass). Model defaults (`gemini-2.5-flash`, `gpt-4.1-mini`, `llama3.1`) are best-effort as of this writing, not guaranteed current — that's exactly why they're overridable rather than locked in.
