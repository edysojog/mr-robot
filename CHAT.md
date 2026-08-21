# MrRobotBot Chat — What We Built

Notes on the interactive chat agent added on top of the existing scan engine, and the three front-ends it ended up with. Written after the fact, so it reads as a record, not a plan.

## Why this exists

The original app was report-only: point it at a folder, get a findings list. This was about making the tool something you *talk to* — closer to Strix's "AI hacker agent" framing, but scoped to fit the app's existing no-infra, report-only boundary (see `TODO.md`'s "Strix-inspired ideas" section for that framing decision).

## The engine: `src/cli/chatCore.js`

Shared, UI-agnostic business logic — extracted out of the original single-file CLI so multiple front-ends could reuse it without drifting apart. Contains:

- **`ChatSession`** — the agentic turn loop. Supports Claude (`tool_use`) and Groq (OpenAI-style function calling) as providers.
- **Three always-on tools**: `scan_project`, `list_findings`, `explain_finding` — wrap the existing scan services (Semgrep/Gitleaks/npm audit/Claude/Groq auditors) and the per-finding chat backend (`chatService.js`).
- **Two opt-in "validation" tools**, gated behind `--enable-validation` (off by default): `http_request` and `run_command`. These are the actual Strix-shaped capability — proving a finding instead of just discussing it. Every single call, regardless of the flag, goes through a `confirmFn` gate showing the exact request/command and requiring explicit approval before it executes. Declining returns a result telling the model not to fabricate what would have happened.
- **`describeToolCall` / `renderToolResult`** — turn a tool call and its result into a display string, tagged with a semantic `kind` (`'tool' | 'tool-result' | 'log'`) so a front-end can style them without re-parsing text.
- **System prompt** widened partway through — it originally implied the agent could *only* respond to scan/finding requests, which made it refuse plain security questions. Now explicitly framed as open-ended conversation, with the tools as something it reaches for only when relevant.

## Front-end 1: `src/cli/chat.js` (Node + Ink)

The first working version. A REPL you run with `npm run chat`. Built on [Ink](https://github.com/vadimdemedes/ink) (the same React-for-CLIs renderer Claude Code itself uses) after an earlier hand-rolled attempt using raw ANSI scroll regions (`DECSTBM`) ran into real rendering bugs under Windows Terminal (a stray trailing line that padding-to-width fixed, among others) — Ink's `<Static>` + non-static render split solved the "scrolling history above a pinned input box" problem properly instead of hand-managing cursor positions.

Still works, still the fallback if Bun isn't installed. Requires `chatCore.js`.

## Front-end 2: `src/cli/chatOpentui.tsx` (Bun + OpenTUI + SolidJS)

The actual stack opencode's own TUI (`packages/tui`) is built on — not an approximation of it. Run with `npm run chat:tui` (which shells out to `bun run src/cli/chatOpentui.tsx`).

**Why a second front-end at all:** asked directly whether the Ink version was "like the Strix chatbot," the honest answer was no — Strix isn't a chatbot at all (confirmed from their own README: "no conversational chat mode," it's a one-shot CLI + report dashboard). Asked instead to match opencode's look, and pushed further to use opencode's *actual* stack rather than reproduce it in Ink. That stack is OpenTUI (`@opentui/core`, a Zig-native renderer) + `@opentui/solid` (SolidJS bindings) + Bun — OpenTUI's native renderer only initializes under Bun or Deno, confirmed empirically (`"OpenTUI native FFI is not available for this runtime yet"` under plain Node), so Bun got installed specifically for this.

New root-level config this needed: `tsconfig.json` (jsx: preserve, jsxImportSource: `@opentui/solid`) and `bunfig.toml` (preload the Solid plugin). Both are scoped to files actually run with `bun` — nothing else in the project touches them.

### Visual design — copied from opencode's real source, not the screenshot

Read `packages/tui/src/routes/session/index.tsx`, `component/spinner.tsx`, and `ui/border.ts` directly rather than guessing from a screenshot. What that source actually does, now mirrored here:

- **Per-tool icons**, not a generic dot — `✱` search, `←` read, `→` write, `%` fetch, `$` shell, mapped onto this app's five tools.
- **An animated spinner replaces the icon while a tool runs**, settling to the static icon on completion — same ten braille frames and 80ms interval opencode uses (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`), which turned out to already match what had been built independently.
- **Assistant replies carry no marker at all** — just body text. Nothing here corresponds to Claude Code's `⏺`; that convention got tried, the user called it out as ugly emoji rather than the Claude Code convention, and it was replaced with opencode's actual (marker-free) approach once the real source was checked.
- **The user-message "blue box"** is a left-only border (`border={["left"]}`, custom border chars with everything but `vertical: "┃"` blanked out) wrapping a padded, background-filled inner box — a bar-plus-panel, not a bordered rectangle.
- **Green phosphor palette**, applied last: `#c8facc` body text, `#39d353` accent (icons/bar/caret), `#5c9c6b` muted (tool output/status), `#0d1710` panel background. The confirm prompt (gating `http_request`/`run_command`) stays inverted — dark-on-bright-green rather than another shade in the same range — specifically so approving a real action doesn't blend into normal scrollback.

### Bugs hit and how they got found

- **"First letter of my input disappears"** — two wrong theories first (a focus race on mount; a terminal-capabilities-handshake race), both disproven by writing an actual reproduction with OpenTUI's `testRender` + `captureCharFrame()` harness instead of guessing a third time. The real cause: the `<input>` had default auto width and was laid out *overlapping* the 2-cell prompt to its left, clipping exactly as many characters as the prompt was wide. Fix: `flexGrow={1}` on the input. Verified against idle/busy/confirm states before calling it done.
- **Gutter misalignment** — tool rows and assistant rows landed one column apart despite "the same" padding, because the padding was baked into the marker string rather than a fixed-width column. Fixed by giving the icon its own `width`-constrained `<text>` instead.

Both fixes were confirmed with `captureCharFrame()`/`captureSpans()` before being called done, not just eyeballed in a live window — OpenTUI's test renderer made that possible without needing the user to re-test each guess.

## Where things stand

- Ink front-end (`chat.js`) and OpenTUI front-end (`chatOpentui.tsx`) both work, share `chatCore.js`, and stay in sync with each other for tool logic — a change to `ChatSession` doesn't need to be made twice.
- `--enable-validation` is off by default in both; every dynamic action still requires interactive confirmation regardless.
- Groq's model catalog moved out from under the original defaults during testing (`llama-3.3-70b-versatile` → 404) — `openai/gpt-oss-120b` is what's currently live; model is a free-text override in both front-ends for exactly this reason.
- A Groq key was pasted directly into chat during testing and used across multiple launches, including being written into `.run_opentui.ps1` on disk. Flagged at the time — rotate it at console.groq.com and delete/scrub that file if it hasn't happened yet.
