# MrRobotBot — Idea Notes

> Exploratory notes from a conversation about whether a "BugBot for security" could work. Nothing built yet — this is the concept writeup.

## The idea

A packaged, read-only security auditor, modeled loosely on BugBot's own architecture (single app → PyInstaller `.exe`). You point it at a project directory, and it produces a report of potential vulnerabilities — no fixing, no auto-remediation, no filing anywhere. Just: "here's what's wrong."

Two versions of the idea came up:

1. **"Cybersecurity BugBot"** — ingest pipeline (scanner output/SIEM alerts/logs) → AI drafts a triaged finding → human reviews → files to a tracker (Jira etc.), same shape as BugBot's actual flow (screenshot → AI drafts bug → review → Jira).
2. **"Claude Code, but for vuln-finding"** (the one actually landed on) — a standalone tool/`.exe` you drop into a project, that scans the whole codebase and reports on its security posture. No ticketing integration, no ingest pipeline — narrower and safer scope than #1.

## Why it's plausible

- BugBot already proves the core pattern works: capture → AI drafts structured output → human reviews before anything becomes "real" (a filed bug / here, a reported finding).
- An LLM is genuinely good at the class of bug that static analysis tools miss — logic-level/architectural issues, like the `/api/config` authless-endpoint blocker found in this same project. No Semgrep rule would have caught that; it required reasoning about the actual request flow.
- Static-analysis tools are good at the opposite: known, well-defined patterns (hardcoded secrets, weak crypto, injection patterns) — deterministic and fast, but not great at "is this authorization logic actually correct."

## Proposed steps to build it

1. **Input**: point it at a project directory (or a git repo/branch).
2. **Static pass**: run language-appropriate SAST tools first — deterministic, fast, catches known patterns.
3. **LLM pass**: feed relevant files/diffs to Claude with a fixed "find vulnerabilities, don't fix, just report" system prompt. Architecturally close to what the `security-review` skill / `/code-review` already do, just scoped to a whole project instead of a diff.
4. **Merge + dedupe**: combine both passes into one findings list, ranked by severity, with file:line references.
5. **Report generation**: structured output (markdown/HTML/JSON). No auto-fix, no auto-filing — just the report.
6. **Packaging**: same PyInstaller approach BugBot uses for its desktop `.exe`, bundling the Claude API calls + static tools into one executable.

A cheaper first version: skip the packaging step entirely and just run `security-review`-style analysis against a whole repo instead of a diff, using Claude Code directly, before investing in a standalone tool.

## Popular static-analysis tools (for the static pass)

**Multi-language / general SAST**
- **Semgrep** — pattern-based, huge community ruleset, easy custom rules, fast. Best default choice for a bot like this.
- **CodeQL** (GitHub) — deeper semantic/dataflow analysis, more powerful but slower/heavier to set up.
- **SonarQube/SonarLint** — broad language coverage, strong on code quality + security, common in enterprise CI.

**Python**: **Bandit** — hardcoded secrets, `eval`, weak crypto, etc.

**JavaScript/Node**: **ESLint** (with `eslint-plugin-security`); **npm audit** / **Snyk** for dependency vulnerabilities.

**Dependency/SCA**: **Snyk**, **Dependabot**, **OWASP Dependency-Check**, **Trivy**.

**Secrets detection**: **Gitleaks**, **TruffleHog**.

**IaC/container**: **Trivy**, **Checkov** — Terraform/Dockerfile/k8s manifest misconfigurations.

Semgrep is the one to reach for first: free, fast, ready-made security rulesets (OWASP-Top-10-style), and its findings are easy to feed into an LLM pass afterward for prioritization/interpretation.

## Would this be useful in a company setting?

Probably yes — the recurring value is catching issues before they reach a security review or production, especially for smaller teams (like this QA/BugBot team) without a dedicated AppSec function reviewing every PR.

**Main tradeoff: trust and noise.**
- Too aggressive → becomes "the tool everyone ignores" (alert fatigue, like a linter nobody reads).
- Too conservative → misses exactly the class of bug that matters most (logic-level auth bypasses like `/api/config`).

**Where it'd likely earn its keep fastest, specifically for this repo:**
- Wired into CI as a required check on `staging` → `main` promotions (which already have a manual "read `debug:kube`" verification step), or
- As a pre-commit/PR gate — catching patterns like the unauthenticated-endpoint issue before they sit in the backlog for months,

rather than as a standalone `.exe` someone has to remember to run manually.

## Open thread

Sketching a CI-integrated version for this repo specifically (`.gitlab-ci.yml` already exists as an integration point) was proposed but not yet done — potential next step if this idea gets picked up.
