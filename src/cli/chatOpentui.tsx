// Bun + OpenTUI + SolidJS front-end -- the actual stack opencode's own TUI
// (packages/tui) is built on, rather than an ANSI approximation of its look.
// Shares ChatSession and the tool logic with the Node + Ink front-end
// (chat.js) via chatCore.js, required here through Bun's CJS interop (Bun
// supports require() from a .tsx entry same as any other module). Reached
// via `mrrobot code`, which locates bun and runs this file -- plain Node
// cannot, OpenTUI's native renderer only initializes under Bun/Deno, which
// is why the dispatcher falls back to chat.js when bun is missing.
//
// Responsiveness and chrome follow opencode's own patterns (its
// packages/tui is the reference): replies stream token-by-token into a live
// markdown row -- chatCore emits deltas through an opt-in hook and its tool
// logic is untouched -- assistant text renders through OpenTUI's
// <markdown>, colors are semantic theme tokens switchable via /themes,
// "/" opens a command palette, ctrl+o toggles full tool output, and the
// footer carries an approximate context meter.

import { render, useKeyboard, usePaste, useRenderer, useTerminalDimensions } from "@opentui/solid";
import { SyntaxStyle } from "@opentui/core";
import { createEffect, createMemo, createRoot, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { createStore } from "solid-js/store";

const path = require("path");
const coreModule = require("./chatCore");
const {
  ChatSession,
  resolveApiKey,
  setWriteOut,
  setAssistantStream,
  CONTEXT_WINDOWS,
  CHAT_DEFAULT_MODEL,
} = coreModule;

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

const HELP = `
MrRobotBot chat (OpenTUI) -- opencode-style terminal UI, Bun-only

Usage:
  mrrobot code [options]

Options:
  --provider <name>       claude | groq | deepseek   (default: claude)
  --model <name>          Model override for the selected provider
  --api-key <key>         API key (or ANTHROPIC_API_KEY / GROQ_API_KEY / DEEPSEEK_API_KEY)
  --cwd <path>            Default folder for scans when you don't name one
  --enable-validation     Adds http_request/run_command tools -- every use still asks to confirm first
  --help                  Show this help

Session commands (type at the prompt):

  /help                   keybinds & commands
  /themes                 switch color theme
  /details                toggle full tool output (also ctrl+o)
  /clear                  start a new conversation
  /exit                   quit the session (also ctrl+c)

Replies stream in as they are generated; tool output collapses to its first
line -- ctrl+o expands it.
`;

type Args = {
  provider: string;
  cwd: string;
  model?: string;
  apiKey?: string;
  enableValidation?: boolean;
  help?: boolean;
};

function parseArgs(argv: string[]): Args {
  const args: Args = { provider: "claude", cwd: process.cwd() };
  const rest = [...argv];
  while (rest.length > 0) {
    const token = rest.shift();
    switch (token) {
      case "--provider": args.provider = rest.shift() as string; break;
      case "--model": args.model = rest.shift(); break;
      case "--api-key": args.apiKey = rest.shift(); break;
      case "--cwd": args.cwd = rest.shift() as string; break;
      case "--enable-validation": args.enableValidation = true; break;
      case "--help": case "-h": args.help = true; break;
      default: break;
    }
  }
  return args;
}

// Gutter conventions taken from opencode's own TUI
// (packages/tui/src/routes/session/index.tsx, the InlineTool component):
// each tool gets a *per-tool* symbol in a 2-cell column, an animated
// spinner replaces that symbol while the tool is running, and nested
// output is simply indented by the same 2 cells -- there is no dot on
// assistant replies and no elbow character on results.
const TOOL_ICON_WIDTH = 2;

// Same frames and interval opencode uses (their component/spinner.tsx).
const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_INTERVAL_MS = 80;

// Icons mapped onto opencode's vocabulary for the nearest equivalent
// action: ✱ for searching, ← for pulling something into context, → for
// emitting, % for a network fetch, $ for a shell command.
const TOOL_ICON: Record<string, string> = {
  scan_project: "✱",
  list_findings: "→",
  explain_finding: "←",
  http_request: "%",
  run_command: "$",
};
const TOOL_ICON_FALLBACK = "→";

// opencode's left-bar treatment for user messages: a border on the left
// edge only, drawn with a heavy vertical bar and blank corners so it
// reads as a bar rather than a box.
const SPLIT_BORDER_CHARS = {
  topLeft: "",
  bottomLeft: "",
  topRight: "",
  bottomRight: "",
  horizontal: " ",
  vertical: "┃",
  bottomT: "",
  topT: "",
  cross: "",
  leftT: "",
  rightT: "",
};

// Rounded corners for dialogs and overlays -- the box style opencode uses
// for its centered dialogs.
const ROUNDED_BORDER_CHARS = {
  topLeft: "╭",
  topRight: "╮",
  bottomLeft: "╰",
  bottomRight: "╯",
  horizontal: "─",
  vertical: "│",
  leftT: "├",
  rightT: "┤",
  topT: "┬",
  bottomT: "┴",
  cross: "┼",
};

type LogKind =
  | "user"        // what you typed -- blue bar, no dot
  | "assistant"   // the model's reply -- green dot
  | "tool"        // a tool about to run -- blue dot
  | "tool-result" // that tool's output -- indented elbow
  | "log"         // incidental progress chatter -- indented, dim, no marker
  | "plain";      // banner and other UI text -- no marker

// `pending` is true for a tool row whose work is still in flight; it drives
// whether the gutter shows the spinner or the settled per-tool icon.
// `tool` is the tool's name, used to pick that icon. `lines` is the
// pre-split line array for tool results, which lets the collapsed view
// show just the summary line without re-splitting on every render.
type LogItem = { id: number; text: string; kind: LogKind; pending?: boolean; tool?: string; lines?: string[] };

// ---------------------------------------------------------------------------
// Themes. Semantic tokens rather than bare constants -- the palette values
// below are the exact green-phosphor colors this TUI has always used, just
// given names (and a second, amber CRT variant to make switching real).
// One place to retune the whole TUI.
// ---------------------------------------------------------------------------
type ThemeTokens = {
  name: string;
  desc: string;
  text: string;     // body text: pale green, kept light enough to read as prose
  accent: string;   // icons, the user-message bar, the prompt caret
  muted: string;    // tool output and status chrome, recedes behind body text
  panel: string;    // near-black with a green cast, for filled panels
  border: string;   // the composer's outline -- barely there, dim by design
  shadow: string;   // the wordmark's drop shadow
  confirmBg: string; // the confirm prompt stays visually loud: inverted
  confirmFg: string;
  composerBar: string; // the indicator bar on the composer's left edge
  link: string;     // markdown link labels
  code: string;     // inline code foreground
  codeBg: string;   // fenced code block background
};

const THEMES: Record<string, ThemeTokens> = {
  mrrobot: {
    name: "mrrobot",
    desc: "green phosphor (default)",
    text: "#c8facc",
    accent: "#39d353",
    muted: "#5c9c6b",
    panel: "#0d1710",
    border: "#1f3a26",
    shadow: "#20502e",
    confirmBg: "#39d353",
    confirmFg: "#04170a",
    composerBar: "#58a6ff", // GitHub blue -- the partner of this theme's GitHub green
    link: "#6fd585",
    code: "#8fe9a8",
    codeBg: "#101c14",
  },
  amber: {
    name: "amber",
    desc: "amber CRT phosphor",
    text: "#ffd489",
    accent: "#ffb000",
    muted: "#a97e2f",
    panel: "#140d02",
    border: "#3d2b0c",
    shadow: "#4a3308",
    confirmBg: "#ffb000",
    confirmFg: "#1a1000",
    composerBar: "#ffb000",
    link: "#e8a83e",
    code: "#ffc857",
    codeBg: "#1c1305",
  },
};

const [themeName, setThemeName] = createSignal<string>("mrrobot");
const t = () => THEMES[themeName()];

// The composer's outline in opencode is barely there -- the panel reads as a
// panel because of its fill, not its edge. A bright edge (the accent) turns it
// into the loudest thing on screen, so the border gets its own dim tone.

// Wordmark ink -> current theme color, resolved at render time so /themes
// recolors even the splash without a restart.
function inkToColor(ink: number): string {
  if (ink === INK_DIM) return t().muted;
  if (ink === INK_BRIGHT) return t().accent;
  if (ink === INK_SHADOW) return t().shadow;
  return t().panel; // INK_NONE: cells with no ink still need a color
}

// Markdown styling through OpenTUI's SyntaxStyle, rebuilt per theme. Scope
// names are the ones OpenTUI's markdown renderer resolves (tree-sitter
// captures + its hardcoded spans); heading levels must each be registered
// because scope fallback only steps down to the first dot segment.
function markdownTheme(c: ThemeTokens) {
  const headingStyle = { fg: c.accent, bold: true };
  const codeStyle = { fg: c.code, bg: c.codeBg };
  const codeBlockStyle = { fg: c.text, bg: c.codeBg };
  return [
    { scope: ["default"], style: { fg: c.text } },
    { scope: ["markup.heading.1"], style: headingStyle },
    { scope: ["markup.heading.2"], style: headingStyle },
    { scope: ["markup.heading.3"], style: headingStyle },
    { scope: ["markup.heading.4"], style: headingStyle },
    { scope: ["markup.heading.5"], style: headingStyle },
    { scope: ["markup.heading.6"], style: headingStyle },
    { scope: ["label"], style: { fg: c.muted } },
    { scope: ["punctuation.special"], style: { fg: c.muted } },
    { scope: ["markup.raw"], style: codeStyle },
    { scope: ["markup.raw.block"], style: codeBlockStyle },
    { scope: ["markup.strong"], style: { fg: c.text, bold: true } },
    { scope: ["markup.italic"], style: { fg: c.text, italic: true } },
    { scope: ["markup.strikethrough"], style: { fg: c.muted, dim: true } },
    { scope: ["markup.link"], style: { fg: c.muted } },
    { scope: ["markup.link.label"], style: { fg: c.link, underline: true } },
    { scope: ["markup.link.url"], style: { fg: c.muted, dim: true } },
    { scope: ["markup.list"], style: { fg: c.accent } },
    { scope: ["markup.quote"], style: { fg: c.muted, italic: true } },
    { scope: ["string.escape"], style: { fg: c.text } },
    { scope: ["character.special"], style: { fg: c.text } },
    { scope: ["keyword.directive"], style: { fg: c.muted } },
  ];
}

// Module-level memo wrapped in createRoot (no owning component) -- one
// native SyntaxStyle per theme switch instead of one per message row.
const mdStyle = createRoot(() =>
  createMemo(() => SyntaxStyle.fromTheme(markdownTheme(t()) as any))
);

// Block-letter splash, following opencode's: a chunky wordmark, two-tone
// (their "open" is dim, "code" is bright), with the version tucked under its
// right edge and a hint list below.
//
// Letters are authored as pixel bitmaps and rendered through half-block
// characters (▀ top pixel, ▄ bottom pixel, █ both), which fits two pixel rows
// into every text row. That doubles the vertical resolution for free and is
// what keeps the curve on R/O/B from reading as a staircase -- drawing
// straight into █ caps a letter at one pixel per row and looks far blockier
// at the same height. Bitmaps also mean the glyphs can be edited as pictures
// rather than as pre-assembled full-width strings, which are impossible to
// keep aligned by hand once a letter changes.
// Kept small deliberately -- 7 pixels wide by 6 tall, so three text rows
// before the shadow adds a fourth. A diagonal drawn across ten rows has to
// step, and those steps are the staircase; at this size every stroke is
// either a full column or a single half-block, so the M's inner peak
// resolves to one ▀ and the O's corners to one ▄/▀ each. Nothing has room
// to staircase. The width is 7 rather than 5 so the counters can hold the
// drop shadow without it closing them up.
const GLYPH_PIXEL_ROWS = 6;
const BITMAPS: Record<string, string[]> = {
  M: [
    "#.....#",
    "##...##",
    "#.#.#.#",
    "#..#..#",
    "#.....#",
    "#.....#",
  ],
  R: [
    "######.",
    "#.....#",
    "#.....#",
    "######.",
    "#...#..",
    "#....##",
  ],
  O: [
    ".#####.",
    "#.....#",
    "#.....#",
    "#.....#",
    "#.....#",
    ".#####.",
  ],
  B: [
    "######.",
    "#.....#",
    "######.",
    "#.....#",
    "#.....#",
    "######.",
  ],
  T: [
    "#######",
    "...#...",
    "...#...",
    "...#...",
    "...#...",
    "...#...",
  ],
};

// The wordmark is composited on a single pixel grid rather than letter by
// letter, because the drop shadow crosses letter boundaries -- one letter's
// shadow falls into the gap before the next, and where it would land on a
// neighbour's stroke the stroke has to win.
//
// Each pixel carries an INK_* layer rather than a plain on/off bit, so a cell
// can hold two different colors: half-block glyphs paint the top half in the
// foreground color and the bottom half in the background color, which is what
// lets a face pixel sit directly above a shadow pixel in the same cell. A
// one-bit grid could not express that and the shadow would break up.
const INK_NONE = 0;
const INK_DIM = 1;    // the "MR" half of the wordmark
const INK_BRIGHT = 2; // the "ROBOT" half
const INK_SHADOW = 3;

const WORDMARK_TEXT = "MRROBOT";
const WORDMARK_DIM_LETTERS = 2; // how many leading letters render dim
// Two, not one: a letter's shadow lands in the column immediately right of
// it, so a single-column gap puts the shadow flush against the next letter's
// stroke and the wordmark reads as one continuous shape.
const LETTER_GAP = 2;
const SHADOW_OFFSET = 1; // pixels, down and to the right

function buildWordmarkGrid(): number[][] {
  const letters = WORDMARK_TEXT.split("");
  const glyphWidth = BITMAPS[letters[0]][0].length;
  const faceWidth = letters.length * glyphWidth + (letters.length - 1) * LETTER_GAP;
  // +SHADOW_OFFSET on each axis for the shadow to fall into, then the row
  // count is rounded up to an even number so the last text row has a bottom
  // pixel row to pair with.
  const width = faceWidth + SHADOW_OFFSET;
  const height = Math.ceil((GLYPH_PIXEL_ROWS + SHADOW_OFFSET) / 2) * 2;
  const grid: number[][] = Array.from({ length: height }, () => new Array(width).fill(INK_NONE));

  const face: [number, number, number][] = [];
  letters.forEach((ch, i) => {
    const ink = i < WORDMARK_DIM_LETTERS ? INK_DIM : INK_BRIGHT;
    const x = i * (glyphWidth + LETTER_GAP);
    BITMAPS[ch].forEach((rowPixels, r) => {
      Array.from(rowPixels).forEach((px, c) => {
        if (px === "#") face.push([r, x + c, ink]);
      });
    });
  });

  for (const [r, c, ink] of face) grid[r][c] = ink;

  // A shadow may only land on space *outside* the letters. Dropping it
  // wherever the offset points also fills the enclosed counters -- the bowls
  // of B, R and O -- and at this size that merges each letter into a solid
  // blob. Light cannot reach an enclosed counter, so flood-fill the exterior
  // from the grid border and keep shadow pixels only there.
  const exterior = Array.from({ length: height }, () => new Array(width).fill(false));
  const queue: [number, number][] = [];
  const visit = (r: number, c: number) => {
    if (r < 0 || r >= height || c < 0 || c >= width) return;
    if (exterior[r][c] || grid[r][c] !== INK_NONE) return;
    exterior[r][c] = true;
    queue.push([r, c]);
  };
  for (let c = 0; c < width; c += 1) { visit(0, c); visit(height - 1, c); }
  for (let r = 0; r < height; r += 1) { visit(r, 0); visit(r, width - 1); }
  while (queue.length > 0) {
    const [r, c] = queue.pop() as [number, number];
    visit(r - 1, c); visit(r + 1, c); visit(r, c - 1); visit(r, c + 1);
  }

  // Only the silhouette casts. Offsetting *every* stroke means a one-pixel
  // bar throws a one-pixel shadow into the open space beneath it, which at
  // this size swallows whatever is down there -- R's leg disappeared under
  // the shadow of R's own middle bar. Casting from just the bottom-most pixel
  // of each column and the right-most of each row keeps the shadow hugging
  // the outline, which is what reads as depth.
  const casters = new Set<string>();
  for (let c = 0; c < width; c += 1) {
    for (let r = height - 1; r >= 0; r -= 1) {
      if (grid[r][c] !== INK_NONE && grid[r][c] !== INK_SHADOW) { casters.add(`${r},${c}`); break; }
    }
  }
  for (let r = 0; r < height; r += 1) {
    for (let c = width - 1; c >= 0; c -= 1) {
      if (grid[r][c] !== INK_NONE && grid[r][c] !== INK_SHADOW) { casters.add(`${r},${c}`); break; }
    }
  }
  for (const key of casters) {
    const [r, c] = key.split(",").map(Number);
    const sr = r + SHADOW_OFFSET;
    const sc = c + SHADOW_OFFSET;
    if (sr < height && sc < width && exterior[sr][sc]) grid[sr][sc] = INK_SHADOW;
  }
  return grid;
}

const WORDMARK_GRID = buildWordmarkGrid();
const LOGO_WIDTH = WORDMARK_GRID[0].length;
const VERSION = `v${require("../../package.json").version}`;

// A wordmark cell carries ink layers rather than resolved colors, so a
// theme switch can recolor the splash without rebuilding the grid.
type WCell = { ch: string; ink: number; bging?: number };

// One text row = two pixel rows. A cell whose halves carry different inks
// becomes ▀ with the lower ink as its background; matching halves collapse to
// a solid █. Runs of identical (char, ink, bgInk) are merged so a row emits a
// handful of cells instead of one per column.
function wordmarkRowSpans(grid: number[][], textRow: number): WCell[] {
  const top = grid[textRow * 2];
  const bottom = grid[textRow * 2 + 1];
  const cells: WCell[] = [];
  for (let c = 0; c < top.length; c += 1) {
    const a = top[c];
    const b = bottom[c];
    let cell: WCell;
    if (a === INK_NONE && b === INK_NONE) cell = { ch: " ", ink: a };
    else if (a === b) cell = { ch: "█", ink: a };
    else if (b === INK_NONE) cell = { ch: "▀", ink: a };
    else if (a === INK_NONE) cell = { ch: "▄", ink: b };
    else cell = { ch: "▀", ink: a, bging: b };

    const prev = cells[cells.length - 1];
    if (prev && prev.ch === cell.ch && prev.ink === cell.ink && prev.bging === cell.bging) {
      prev.ch += cell.ch;
    } else {
      cells.push(cell);
    }
  }
  return cells;
}

// Phrased as things to type, not slash commands -- phrasing kept from the
// original splash; the actual command surface lives in the "/" palette.
const SPLASH_HINTS: [string, string][] = [
  ["scan this folder", "run the full scan pipeline"],
  ["what did you find", "list findings from the last scan"],
  ["explain finding 3", "dig into one finding"],
  ["/exit", "quit the session"],
];

const WORDMARK_ROWS: WCell[][] = Array.from(
  { length: WORDMARK_GRID.length / 2 },
  (_, row) => wordmarkRowSpans(WORDMARK_GRID, row)
);

const KEY_FIELD_WIDTH = 52;
const HINT_COLUMN = 20;
const HINT_WIDTH = HINT_COLUMN + Math.max(...SPLASH_HINTS.map(([, desc]) => desc.length));

// The banner block above the conversation: wordmark, then the session's
// provider/folder line, then the hints. Lives inside the scrollbox so it
// scrolls away as the conversation grows rather than pinning to the top.
// Shared by the splash and the API-key screen, so the two openings of the
// app look like the same app.
function Wordmark() {
  // The wordmark is a fixed-width block and cannot reflow. Centered in a
  // narrower terminal it gets clipped at *both* ends -- losing the M and the
  // T -- so below its width it drops to a plain-text title instead.
  const dims = useTerminalDimensions();
  const roomForWordmark = () => dims().width >= LOGO_WIDTH + 4;

  return (
    <>
      {roomForWordmark() ? (
        <box flexDirection="column" flexShrink={0}>
          <For each={WORDMARK_ROWS}>
            {(cells) => (
              <box flexDirection="row">
                <For each={cells}>
                  {(cell) => (
                    <text fg={inkToColor(cell.ink)} bg={cell.bging != null ? inkToColor(cell.bging) : undefined}>
                      {cell.ch}
                    </text>
                  )}
                </For>
              </box>
            )}
          </For>
          {/* Version sits under the wordmark's right edge, as opencode's does. */}
          <box width={LOGO_WIDTH} flexShrink={0} justifyContent="flex-end" flexDirection="row">
            <text fg={t().muted}>{VERSION}</text>
          </box>
        </box>
      ) : (
        <box flexDirection="row" flexShrink={0}>
          <text fg={t().muted}>MR</text>
          <text fg={t().accent}>ROBOT </text>
          <text fg={t().muted}>{VERSION}</text>
        </box>
      )}
    </>
  );
}

// The banner block above the conversation: wordmark, then the session's
// provider/folder line, then the hints. Lives inside the scrollbox so it
// scrolls away as the conversation grows rather than pinning to the top.
function Splash(props: { banner: string }) {
  // The hint rows are a fixed-width two-column block and clip the same way
  // the wordmark does -- at both ends, since they are centered. There is no
  // useful narrow rendering of them, so they just drop out.
  const dims = useTerminalDimensions();
  const roomForHints = () => dims().width >= HINT_WIDTH + 4;

  // alignItems="center" centers each child on its own natural width, so the
  // wordmark, the banner line and the hint block each get centered as a
  // unit -- while the hint rows stay left-aligned *within* that block, which
  // is what keeps their two columns lined up with each other.
  return (
    <box flexDirection="column" alignItems="center" marginTop={1} marginBottom={1} flexShrink={0}>
      <Wordmark />
      <box marginTop={1} flexShrink={0}>
        <text fg={t().muted}>{props.banner}</text>
      </box>
      <Show when={roomForHints()}>
        <box flexDirection="column" marginTop={1} flexShrink={0}>
          <For each={SPLASH_HINTS}>
            {([cmd, desc]) => (
              <box flexDirection="row">
                <text width={HINT_COLUMN} flexShrink={0} fg={t().text}>{cmd}</text>
                <text fg={t().muted}>{desc}</text>
              </box>
            )}
          </For>
        </box>
      </Show>
    </box>
  );
}

// Sourced from chatCore rather than restated here: a provider added there
// but missed here would be selectable via --provider yet absent from the key
// screen's tab cycle.
const PROVIDERS: string[] = coreModule.CHAT_PROVIDERS;
const ENV_VAR: Record<string, string> = coreModule.CHAT_ENV_VAR;

// Shown instead of the chat when no key could be resolved, rather than
// printing a line and exiting -- which left you at a shell prompt having to
// go find the flag name.
//
// Keys are captured through useKeyboard rather than an <input>, because
// OpenTUI's input has no mask option and renders whatever it holds. An API
// key should not be echoed into terminal scrollback, so the real value lives
// in a signal here and only bullets are ever drawn. usePaste is wired up
// too -- nobody types one of these by hand.
export function ApiKeyPrompt(props: { provider: string; onSubmit: (provider: string, key: string) => void }) {
  const [provider, setProvider] = createSignal(props.provider);
  const [key, setKey] = createSignal("");
  const [error, setError] = createSignal("");
  watchTerminalSize();
  const quit = useQuit();

  // Switching provider re-checks that provider's env var -- someone with
  // GROQ_API_KEY set who lands here because --provider defaulted to claude
  // should be able to tab over and continue without pasting anything.
  const envKey = () => process.env[ENV_VAR[provider()]] || "";

  const submit = () => {
    const typed = key().trim() || envKey();
    if (!typed) {
      setError(`No key entered. Paste one, or set ${ENV_VAR[provider()]} and restart.`);
      return;
    }
    props.onSubmit(provider(), typed);
  };

  useKeyboard((e: any) => {
    if (e.ctrl && e.name === "c") return quit();
    if (e.name === "tab") {
      const i = PROVIDERS.indexOf(provider());
      setProvider(PROVIDERS[(i + 1) % PROVIDERS.length]);
      setError("");
      return;
    }
    if (e.name === "return" || e.name === "enter") { submit(); return; }
    if (e.name === "backspace") { setKey((k) => k.slice(0, -1)); return; }
    // Printable single characters only: this filters out arrows, function
    // keys and control chords, whose sequences are multi-byte escapes.
    if (!e.ctrl && !e.meta && e.sequence && e.sequence.length === 1 && e.sequence >= " ") {
      setKey((k) => k + e.sequence);
      setError("");
    }
  });

  usePaste((event: any) => {
    const text = new TextDecoder().decode(event.bytes).replace(/\s+/g, "");
    if (text) { setKey((k) => k + text); setError(""); }
  });

  return (
    <box flexDirection="column" width="100%" height="100%">
      <box flexGrow={1} justifyContent="center" alignItems="center">
        <box flexDirection="column" alignItems="center" flexShrink={0}>
          <Wordmark />
          <box marginTop={1} flexShrink={0}>
            <text fg={t().muted}>No API key found. Paste one to get started.</text>
          </box>

          <box flexDirection="row" marginTop={1} flexShrink={0}>
            <For each={PROVIDERS}>
              {(name) => (
                <text
                  fg={provider() === name ? t().confirmFg : t().muted}
                  bg={provider() === name ? t().accent : t().panel}
                >
                  {` ${name} `}
                </text>
              )}
            </For>
            <text fg={t().muted}>{"  tab to switch"}</text>
          </box>

          <box
            border
            borderColor={t().border}
            backgroundColor={t().panel}
            paddingLeft={1}
            paddingRight={1}
            marginTop={1}
            width={KEY_FIELD_WIDTH}
            flexShrink={0}
            flexDirection="row"
          >
            <text fg={t().accent}>{"› "}</text>
            <text fg={t().text}>
              {key().length > 0
                ? "•".repeat(Math.min(key().length, KEY_FIELD_WIDTH - 6))
                : (envKey() ? `using ${ENV_VAR[provider()]}` : "")}
            </text>
          </box>

          <box marginTop={1} flexShrink={0}>
            <text fg={error() ? t().accent : t().muted}>
              {error() || `enter to continue · ctrl+c to quit`}
            </text>
          </box>
          <box flexShrink={0}>
            <text fg={t().muted}>
              {`skip this next time by setting ${ENV_VAR[provider()]}`}
            </text>
          </box>
        </box>
      </box>
    </box>
  );
}

// Quitting has to hand the terminal back before the process goes away.
//
// OpenTUI runs in the alternate screen buffer, which has no scrollback of
// its own, and it registers its cleanup (renderer.destroy(), which restores
// the main buffer and disables mouse tracking) against *signals* --
// SIGINT/SIGTERM/SIGQUIT and friends. A bare process.exit() delivers no
// signal, so none of that runs: the shell comes back still pointed at the
// alternate buffer with mouse reporting on, and scrolling appears dead
// until the terminal is reset. Calling destroy() first is what makes
// ctrl+c leave the terminal usable.
function useQuit() {
  const renderer = useRenderer();
  return () => {
    try {
      renderer.destroy();
    } finally {
      process.exit(0);
    }
  };
}

// OpenTUI learns about terminal resizes from SIGWINCH alone. Node only
// promises that signal on POSIX -- on Windows it documents delivery as
// happening "on write to the console when the cursor is being moved", so
// going fullscreen leaves the renderer sized to the old window and every
// centered thing lines up against a stale width. Polling stdout's reported
// size closes that gap; the comparison against the renderer's own dimensions
// means it is a no-op wherever SIGWINCH already did the job.
const RESIZE_POLL_MS = 250;

function watchTerminalSize() {
  const renderer = useRenderer();
  onMount(() => {
    const stdout = process.stdout as NodeJS.WriteStream;
    if (!stdout?.isTTY) return; // e.g. the test renderer, which drives its own size
    const timer = setInterval(() => {
      const { columns, rows } = stdout;
      if (!columns || !rows) return;
      if (columns !== renderer.terminalWidth || rows !== renderer.terminalHeight) {
        renderer.resize(columns, rows);
      }
    }, RESIZE_POLL_MS);
    onCleanup(() => clearInterval(timer));
  });
}

// A single shared clock drives every spinner on screen, so they all rotate
// in phase instead of each row animating on its own offset. Returns the
// current frame glyph; the interval is torn down with the component that
// created it.
function createSpinner() {
  const [tick, setTick] = createSignal(0);
  const timer = setInterval(() => setTick((t) => t + 1), SPINNER_INTERVAL_MS);
  onCleanup(() => clearInterval(timer));
  return () => SPINNER_FRAMES[tick() % SPINNER_FRAMES.length];
}

// Slash-command surface, mirroring opencode's vocabulary where the actions
// overlap. Aliases match the ones users type by reflex.
type CommandDef = { name: string; desc: string; aliases: string[] };
const COMMANDS: CommandDef[] = [
  { name: "help", desc: "keybinds & commands", aliases: [] },
  { name: "themes", desc: "switch color theme", aliases: ["theme"] },
  { name: "details", desc: "toggle full tool output", aliases: [] },
  { name: "clear", desc: "start a new conversation", aliases: ["new"] },
  { name: "exit", desc: "quit the session", aliases: ["quit"] },
];

// Titlecased provider name for the composer meta row, the way opencode
// titlecases its agent name.
const PROVIDER_TITLE: Record<string, string> = { claude: "Claude", groq: "Groq", deepseek: "DeepSeek" };
const providerTitle = (p: string) => PROVIDER_TITLE[p] ?? p.charAt(0).toUpperCase() + p.slice(1);

// Display label for the provider org, the muted word trailing the model id
// in opencode's composer ("Build · model OpenCode Zen").
const PROVIDER_ORG: Record<string, string> = { claude: "Anthropic", groq: "Groq", deepseek: "DeepSeek" };

// opencode's footer context reads "204.4K (20%)" -- same shape here.
function fmtTokens(n: number): string {
  return n >= 1000 ? `${(Math.round(n / 100) / 10).toFixed(1)}K` : `${n}`;
}

// Centered overlay frame -- opencode draws its dialogs as rounded panels
// floating over the transcript rather than replacing it, so the backdrop is
// deliberately transparent.
function DialogFrame(props: { title: string; width: number; children?: any }) {
  return (
    <box position="absolute" top={0} left={0} width="100%" height="100%" justifyContent="center" alignItems="center">
      <box
        flexDirection="column"
        width={props.width}
        border
        borderColor={t().border}
        backgroundColor={t().panel}
        customBorderChars={ROUNDED_BORDER_CHARS}
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
      >
        <box flexDirection="row" justifyContent="space-between">
          <text fg={t().accent}>{props.title}</text>
          <text fg={t().muted}>esc close</text>
        </box>
        {props.children}
      </box>
    </box>
  );
}

function HelpDialog(props: { onClose: () => void }) {
  useKeyboard((e: any) => {
    if (e.name === "escape" || e.name === "return" || e.name === "enter") props.onClose();
  });
  const ROWS: [string, string][] = [
    ["enter", "send message · run selected command"],
    ["ctrl+p", "command palette"],
    ["ctrl+o", "toggle full tool output"],
    ["ctrl+c", "quit MrRobotBot"],
    ["↑ ↓", "move through menus"],
    ["esc", "close dialogs"],
  ];
  return (
    <DialogFrame title="keybinds" width={54}>
      <box flexDirection="column" marginTop={1}>
        <For each={ROWS}>
          {([k, d]) => (
            <box flexDirection="row">
              <text width={10} flexShrink={0} fg={t().accent}>{k}</text>
              <text fg={t().text}>{d}</text>
            </box>
          )}
        </For>
      </box>
    </DialogFrame>
  );
}

function ThemeDialog(props: { onClose: () => void; onApply: (name: string) => void }) {
  const names = Object.keys(THEMES);
  const [sel, setSel] = createSignal(Math.max(0, names.indexOf(themeName())));
  useKeyboard((e: any) => {
    if (e.name === "escape") return props.onClose();
    if (e.name === "up") return setSel((i) => Math.max(0, i - 1));
    if (e.name === "down") return setSel((i) => Math.min(names.length - 1, i + 1));
    if (e.name === "return" || e.name === "enter") {
      const name = names[sel()];
      setThemeName(name);
      props.onApply(name);
      props.onClose();
    }
  });
  return (
    <DialogFrame title="theme" width={44}>
      <box flexDirection="column" marginTop={1}>
        <For each={names}>
          {(name, i) => (
            <box flexDirection="row">
              <text width={12} flexShrink={0} fg={i() === sel() ? t().confirmFg : t().accent} bg={i() === sel() ? t().accent : t().panel}>
                {name}
              </text>
              <text flexGrow={1} fg={i() === sel() ? t().confirmFg : t().muted} bg={i() === sel() ? t().accent : t().panel}>
                {THEMES[name].desc}
              </text>
            </box>
          )}
        </For>
      </box>
    </DialogFrame>
  );
}

// One entry in the scrollback, following opencode's InlineTool structure:
// a 2-cell icon column with the body beside it, so a wrapped body stays
// aligned under itself rather than sliding back under the icon.
function LogRow(props: { item: LogItem; spinner: () => string; showDetails: () => boolean }) {
  const kind = () => props.item.kind;

  // User message: a heavy left bar with a filled panel beside it, drawn
  // as a left-only border the way opencode's UserMessage does, rather
  // than a bar character glued onto the text.
  if (kind() === "user") {
    return (
      <box
        border={["left"]}
        borderColor={t().accent}
        customBorderChars={SPLIT_BORDER_CHARS}
        marginTop={1}
        marginBottom={1}
        flexShrink={0}
      >
        <box paddingTop={1} paddingBottom={1} paddingLeft={2} backgroundColor={t().panel} flexShrink={0}>
          <text fg={t().text}>{props.item.text}</text>
        </box>
      </box>
    );
  }

  // Assistant replies render as markdown through OpenTUI's renderer -- the
  // same element opencode builds its message list on. Tool-free plain UI
  // text stays a bare <text>.
  if (kind() === "assistant") {
    return (
      <box marginTop={1} flexShrink={0} flexDirection="column">
        <markdown content={props.item.text} syntaxStyle={mdStyle()} conceal={true} />
      </box>
    );
  }

  if (kind() === "plain") {
    return (
      <box flexShrink={0}>
        <text fg={t().text}>{props.item.text}</text>
      </box>
    );
  }

  // Tool output hangs under the icon column. Collapsed by default to its
  // summary line (opencode hides execution details behind a toggle too);
  // ctrl+o expands everything.
  if (kind() === "tool-result") {
    const lines = props.item.lines ?? props.item.text.split("\n");
    const collapsed = () => !props.showDetails() && lines.length > 1;
    return (
      <box paddingLeft={TOOL_ICON_WIDTH} flexDirection="column" flexShrink={0}>
        <For each={collapsed() ? lines.slice(0, 1) : lines}>
          {(line) => <text fg={t().muted}>{line}</text>}
        </For>
        <Show when={collapsed()}>
          <text fg={t().muted}>{`… ${lines.length - 1} more lines · ctrl+o expands`}</text>
        </Show>
      </box>
    );
  }

  if (kind() === "log") {
    return (
      <box paddingLeft={TOOL_ICON_WIDTH}>
        <text fg={t().muted}>{props.item.text}</text>
      </box>
    );
  }

  // A tool: spinner while it runs, its own icon once settled.
  return (
    <box flexDirection="row" marginTop={1}>
      <text width={TOOL_ICON_WIDTH} flexShrink={0} fg={t().accent}>
        {props.item.pending ? props.spinner() : (TOOL_ICON[props.item.tool ?? ""] ?? TOOL_ICON_FALLBACK)}
      </text>
      <text flexGrow={1} fg={t().text}>{props.item.text}</text>
    </box>
  );
}

export function App(props: { session: any; banner: string }) {
  // Store, not signal-of-array: patching one row's `pending` flag mutates in
  // place, so Solid's keyed <For> never remounts a settled row -- the old
  // map-to-new-objects approach recreated every spinning item exactly when
  // a tool finished, which flickered precisely at the moment of interest.
  const [logs, setLogs] = createStore<LogItem[]>([]);
  const [value, setValue] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  // Holds the pending confirm() resolver while a validation-tool call is
  // waiting on a y/n answer -- non-null means the input line is currently
  // acting as that confirm prompt instead of the normal chat box.
  const [confirmResolve, setConfirmResolve] = createSignal<((v: boolean) => void) | null>(null);
  // Accumulates the assistant reply while it streams; flushed into liveText
  // on a coalescing timer so a burst of deltas paints once, like opencode's
  // batched updates, instead of once per chunk.
  const [liveText, setLiveText] = createSignal("");
  const [dialog, setDialog] = createSignal<null | "help" | "themes">(null);
  // Full tool cards visible by default (as this TUI always showed them);
  // ctrl+o or /details collapses long output to its summary line.
  const [showDetails, setShowDetails] = createSignal(true);
  const [cmdIndex, setCmdIndex] = createSignal(0);
  const [toastMsg, setToastMsg] = createSignal<string | null>(null);
  const [ctxPct, setCtxPct] = createSignal(0);
  // Footer status item -- mirrors opencode's "• N LSP" slot with the thing
  // this app actually has to count.
  const [findingsCount, setFindingsCount] = createSignal(0);
  const [ctxTokens, setCtxTokens] = createSignal(0);

  const spinner = createSpinner();
  watchTerminalSize();
  const quit = useQuit();
  let idCounter = 0;
  let inputRef: any;

  // --- streaming buffers ---------------------------------------------------
  const FLUSH_MS = 40;
  let deltaBuf = "";
  let deltaTimer: ReturnType<typeof setTimeout> | null = null;
  let toastTimer: ReturnType<typeof setTimeout> | null = null;
  let sawDeltas = false;          // did this turn stream anything?
  let producedLiveRowThisTurn = 0; // assistant rows appended from the stream

  function flushDeltaBuf() {
    if (deltaTimer) { clearTimeout(deltaTimer); deltaTimer = null; }
    if (!deltaBuf) return;
    const chunk = deltaBuf;
    deltaBuf = "";
    setLiveText((v) => v + chunk);
  }

  // Turns whatever streamed so far into a settled transcript row. Called at
  // tool boundaries (so text emitted before a tool_use lands above its
  // trace) and at end of turn (so the final reply isn't pushed twice).
  function finalizeLive() {
    flushDeltaBuf();
    const text = liveText();
    if (!text.trim()) { setLiveText(""); return; }
    idCounter += 1;
    setLogs(logs.length, { id: idCounter, text, kind: "assistant" });
    setLiveText("");
    producedLiveRowThisTurn += 1;
  }

  function settlePending() {
    // In-place property patches only -- no object replacement, no remounts.
    // Called when a tool reports its result, and again when a turn ends --
    // the second call matters because some tools render no result at all
    // (renderToolResult returns '' and the row is skipped), which would
    // otherwise leave a row spinning forever.
    for (let i = 0; i < logs.length; i += 1) {
      const l = logs[i];
      if (l.pending) setLogs(i, "pending", false);
    }
  }

  function pushLog(text: string, kind: LogKind = "plain", meta?: { tool?: string }) {
    // Streamed text already on screen settles above a tool trace, keeping
    // the model's words and the tool run in chronological order.
    if (kind === "tool" || kind === "log") finalizeLive();
    idCounter += 1;
    let clean = stripAnsi(text).replace(/\n+$/, "");
    // chatCore prefixes tool traces with "→ " and indents its scan chatter,
    // both of which are that front-end's stand-in for a gutter. Here the
    // icon column already conveys it, so strip them rather than render two
    // markers side by side.
    if (kind === "tool") clean = clean.replace(/^→\s*/, "");
    if (kind === "log") clean = clean.trimStart();
    if (!clean) return;
    // A result (or the next tool starting) means whatever was spinning is
    // done -- settle it before appending the new row.
    if (kind === "tool-result" || kind === "tool") settlePending();
    setLogs(logs.length, {
      id: idCounter,
      text: clean,
      kind,
      pending: kind === "tool",
      tool: meta?.tool,
      lines: kind === "tool-result" ? clean.split("\n") : undefined,
    });
  }

  function showToast(msg: string) {
    setToastMsg(msg);
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => setToastMsg(null), 2200);
  }

  function toggleDetails() {
    const next = !showDetails();
    setShowDetails(next);
    showToast(next ? "tool details on" : "tool details off");
  }

  function refreshCtx() {
    try {
      const win = (CONTEXT_WINDOWS as Record<string, number>)[props.session.provider] || 128000;
      const tokens = typeof props.session.estimateContextTokens === "function"
        ? props.session.estimateContextTokens()
        : 0;
      setCtxPct(Math.min(99, Math.round((tokens / win) * 100)));
      setCtxTokens(tokens);
      setFindingsCount(props.session.lastScan?.findings?.length ?? 0);
    } catch {
      /* meter is best-effort */
    }
  }

  // Rotating placeholder, opencode-style ("Ask anything... \"<example>\"")
  // fed from the splash's own hint phrases so the two never drift apart.
  const PLACEHOLDER_EXAMPLES = SPLASH_HINTS.map(([cmd]) => cmd).filter((cmd) => !cmd.startsWith("/"));
  const [placeholderIdx, setPlaceholderIdx] = createSignal(0);
  onMount(() => {
    if (PLACEHOLDER_EXAMPLES.length < 2) return;
    const timer = setInterval(
      () => setPlaceholderIdx((i) => (i + 1) % PLACEHOLDER_EXAMPLES.length),
      6000
    );
    onCleanup(() => clearInterval(timer));
  });
  const placeholderText = () =>
    `Ask anything... "${PLACEHOLDER_EXAMPLES[placeholderIdx()]}"`;

  // Slash palette visibility derives straight from the input text, the way
  // opencode's does: typing "/" is opening it.
  const filteredCommands = createMemo(() => {
    const q = value().slice(1).trim().toLowerCase();
    if (!q) return COMMANDS;
    return COMMANDS.filter(
      (c) => c.name.includes(q) || c.aliases.some((a) => a.includes(q)) || c.desc.toLowerCase().includes(q)
    );
  });
  const paletteVisible = () => !dialog() && !confirmResolve() && value().startsWith("/");
  // Keep the highlight inside the list as the filter shrinks it, and reset
  // it whenever the query changes.
  createEffect(() => {
    value();
    setCmdIndex(0);
  });
  createEffect(() => {
    const n = filteredCommands().length;
    if (cmdIndex() >= n) setCmdIndex(Math.max(0, n - 1));
  });

  function runCommand(name: string) {
    switch (name) {
      case "help":
        setDialog("help");
        break;
      case "themes":
      case "theme":
        setDialog("themes");
        break;
      case "details":
        toggleDetails();
        break;
      case "clear":
      case "new":
        if (busy()) { showToast("wait for this turn to finish"); return; }
        // Fresh conversation: drop the LLM history and the transcript, but
        // keep lastScan -- findings survive and stay explorable.
        props.session.messages = undefined;
        deltaBuf = "";
        if (deltaTimer) { clearTimeout(deltaTimer); deltaTimer = null; }
        setLiveText("");
        setLogs([] as any);
        setCtxPct(0);
        setFindingsCount(0);
        showToast("new conversation");
        break;
      case "exit":
      case "quit":
        quit();
        break;
    }
  }

  onMount(() => {
    // chatCore tags each write with its kind ('tool' | 'tool-result' |
    // 'log'); anything untagged is plain UI text. Deltas arrive through the
    // separate opt-in hook and coalesce before painting.
    setWriteOut((text: string, kind: LogKind = "plain", meta?: { tool?: string }) => pushLog(text, kind, meta));
    setAssistantStream((chunk: string) => {
      sawDeltas = true;
      deltaBuf += chunk;
      if (!deltaTimer) {
        deltaTimer = setTimeout(() => {
          deltaTimer = null;
          flushDeltaBuf();
        }, FLUSH_MS);
      }
    });
    props.session.confirmFn = (message: string) =>
      new Promise<boolean>((resolve) => {
        finalizeLive();
        pushLog(message);
        setConfirmResolve(() => resolve);
      });
    // The banner is rendered by <Splash>, not pushed as a log row.
    inputRef?.focus?.();
  });

  onCleanup(() => {
    setAssistantStream(null);
    if (deltaTimer) clearTimeout(deltaTimer);
    if (toastTimer) clearTimeout(toastTimer);
  });

  useKeyboard((key: any) => {
    if (key.ctrl && key.name === "c") return quit();
    if (dialog()) return; // open dialogs consume their own keys
    if (key.ctrl && key.name === "o") return toggleDetails();
    // opencode's command-palette keybind -- opens our "/" palette.
    if (key.ctrl && key.name === "p") {
      setValue("/");
      setCmdIndex(0);
      return;
    }
    if (paletteVisible()) {
      if (key.name === "up") { setCmdIndex((i) => Math.max(0, i - 1)); return; }
      if (key.name === "down") { setCmdIndex((i) => Math.min(filteredCommands().length - 1, i + 1)); return; }
      if (key.name === "escape") { setValue(""); return; }
    }
  });

  async function handleSubmit(raw: string) {
    const text = raw.trim();

    // The confirm gate outranks everything -- including the palette, which
    // is hidden anyway while a y/n answer is pending.
    const resolve = confirmResolve();
    if (resolve) {
      const approved = text.toLowerCase() === "y";
      setConfirmResolve(null);
      setValue("");
      pushLog(approved ? "confirmed." : "declined.");
      resolve(approved);
      return;
    }

    // While the palette is visible Enter selects from it rather than
    // submitting to the model.
    if (paletteVisible()) {
      const items = filteredCommands();
      if (items.length === 0) {
        showToast(`unknown command: ${value()}`);
        setValue("");
        return;
      }
      const cmd = items[Math.min(cmdIndex(), items.length - 1)];
      setValue("");
      runCommand(cmd.name);
      return;
    }

    setValue("");

    // The input stays mounted even while busy (see the JSX below) so it
    // never loses focus mid-conversation -- this guard is what actually
    // stops a second turn from starting if Enter is pressed while one is
    // already running.
    if (busy()) return;

    if (!text) return;

    pushLog(text, "user");
    sawDeltas = false;
    producedLiveRowThisTurn = 0;
    setBusy(true);
    try {
      const reply = await props.session.turn(text);
      settlePending();
      finalizeLive();
      // With streaming wired up the reply already reached the screen token
      // by token; pushing it again would duplicate the turn. The fallback
      // covers providers/paths that produced no deltas at all.
      if (!producedLiveRowThisTurn && reply && reply.trim()) pushLog(reply, "assistant");
      refreshCtx();
    } catch (err: any) {
      settlePending();
      finalizeLive();
      pushLog(`error: ${err.message}`, "assistant");
    }
    setBusy(false);
  }

  const confirming = () => confirmResolve() !== null;
  // The model id the turn loop will actually use -- session.model when
  // given, otherwise the provider's default from chatCore. Showing it keeps
  // the meta row in opencode's "Agent · model" shape instead of a bare
  // provider name.
  const effectiveModel = () =>
    props.session.model || (CHAT_DEFAULT_MODEL as Record<string, string>)[props.session.provider];
  const hasContent = () => logs.length > 0 || liveText().length > 0;

  return (
    <box flexDirection="column" width="100%" height="100%">
      {/*
        Two layouts, not one. An empty session shows the splash centered in
        the whole area above the composer, which a scrollbox cannot do -- its
        content has no height to center within, so the splash would sit pinned
        to the top. Once the first message lands the scrollbox takes over and
        the splash becomes ordinary scrollback at the top of the transcript.
      */}
      <Show
        when={hasContent()}
        fallback={
          <box flexGrow={1} justifyContent="center" alignItems="center">
            <Splash banner={props.banner} />
          </box>
        }
      >
        <scrollbox flexGrow={1} stickyScroll stickyStart="bottom" paddingX={1}>
          <Splash banner={props.banner} />
          {/* Keyed on the theme name: a theme switch rebuilds the markdown
              rows so their fresh SyntaxStyle is applied natively. */}
          <Show when={themeName()} keyed>
            {(currentTheme: string) => (
              <>
                <For each={logs}>
                  {(item) => <LogRow item={item} spinner={spinner} showDetails={showDetails} />}
                </For>
                <Show when={liveText()}>
                  <box marginTop={1} flexShrink={0} flexDirection="column">
                    <markdown content={liveText()} syntaxStyle={mdStyle()} conceal={true} streaming={true} />
                  </box>
                </Show>
              </>
            )}
          </Show>
        </scrollbox>
      </Show>

      {/*
        The bottom section mirrors opencode's session route: a plain filled
        composer panel (no edge ink) with its meta row *inside*, then their
        Footer -- working directory on the left, status items on the right.
      */}
      <box flexDirection="column" marginTop={1} paddingX={1} flexShrink={0}>
        <box
          border={["left"]}
          borderColor={confirming() ? t().confirmBg : t().composerBar}
          customBorderChars={SPLIT_BORDER_CHARS}
          backgroundColor={confirming() ? t().confirmBg : t().panel}
          flexShrink={0}
        >
          <box flexDirection="column" paddingLeft={2} paddingRight={2} paddingTop={1} paddingBottom={1}>
            <input
              ref={(el: any) => { inputRef = el; }}
              flexGrow={1}
              value={value()}
              focused={!dialog()}
              placeholder={confirming() ? "type y to approve · anything else declines" : placeholderText()}
              placeholderColor={confirming() ? t().confirmFg : t().muted}
              textColor={confirming() ? t().confirmFg : t().accent}
              focusedTextColor={confirming() ? t().confirmFg : t().accent}
              cursorColor={confirming() ? t().confirmFg : t().accent}
              backgroundColor={confirming() ? t().confirmBg : t().panel}
              focusedBackgroundColor={confirming() ? t().confirmBg : t().panel}
              onInput={setValue}
              onSubmit={handleSubmit}
            />
            {/*
              The meta row opencode keeps under the prompt text: identity on
              the left (theirs is agent · model · provider), transient state
              on the right (theirs is a plugin slot).
            */}
            <box flexDirection="row" justifyContent="space-between" paddingTop={1} gap={1}>
              <box flexDirection="row" gap={1} flexShrink={0}>
                <Show when={!busy()} fallback={
                  <text fg={confirming() ? t().confirmFg : t().muted} bg={confirming() ? t().confirmBg : t().panel}>
                    {`${spinner()} working…`}
                  </text>
                }>
                  <text fg={confirming() ? t().confirmFg : t().accent} bg={confirming() ? t().confirmBg : t().panel}>
                    {providerTitle(props.session.provider)}
                  </text>
                  <Show when={effectiveModel()}>
                    <text fg={confirming() ? t().confirmFg : t().muted} bg={confirming() ? t().confirmBg : t().panel}>·</text>
                    <text fg={confirming() ? t().confirmFg : t().text} bg={confirming() ? t().confirmBg : t().panel}>
                      {effectiveModel()}
                    </text>
                    <text fg={confirming() ? t().confirmFg : t().muted} bg={confirming() ? t().confirmBg : t().panel}>
                      {PROVIDER_ORG[props.session.provider] ?? props.session.provider}
                    </text>
                  </Show>
                </Show>
              </box>
            </box>
          </box>
    </box>
        {/* opencode's Footer verbatim in structure: directory left, items right */}
        <box flexDirection="row" justifyContent="space-between" gap={1} marginTop={1}>
          <text fg={t().muted}>{props.session.defaultCwd}</text>
          <box flexDirection="row" gap={2} flexShrink={0}>
            <Show when={findingsCount() > 0}>
              <text fg={t().text}>{`${TOOL_ICON.scan_project} ${findingsCount()} finding${findingsCount() === 1 ? "" : "s"}`}</text>
            </Show>
            <Show when={ctxTokens() > 0}>
              <text fg={t().text}>{`${fmtTokens(ctxTokens())} (${ctxPct()}%)`}</text>
            </Show>
            <text fg={t().muted}>ctrl+p commands</text>
          </box>
        </box>
      </box>

      {/*
        Overlays sit after the composer in tree order so they draw on top.
        The slash palette anchors just above the composer, bottom-left --
        where the eye already is while typing.
      */}
      <Show when={paletteVisible()}>
        <box position="absolute" bottom={7} left={1} width={50} flexDirection="column">
          <box
            flexDirection="column"
            border
            borderColor={t().border}
            backgroundColor={t().panel}
            customBorderChars={ROUNDED_BORDER_CHARS}
            paddingLeft={1}
            paddingRight={1}
            paddingTop={0}
            paddingBottom={0}
          >
            <For each={filteredCommands().slice(0, 6)}>
              {(cmd, i) => {
                // NOTE: the comparison must live inside the JSX attributes --
                // a const computed here would run once and never react to
                // arrow-key changes.
                return (
                  <box flexDirection="row">
                    <text
                      width={11}
                      flexShrink={0}
                      fg={i() === cmdIndex() ? t().confirmFg : t().accent}
                      bg={i() === cmdIndex() ? t().confirmBg : t().panel}
                    >
                      {`/${cmd.name}`}
                    </text>
                    <text
                      flexGrow={1}
                      fg={i() === cmdIndex() ? t().confirmFg : t().muted}
                      bg={i() === cmdIndex() ? t().confirmBg : t().panel}
                    >
                      {cmd.desc}
                    </text>
                  </box>
                );
              }}
            </For>
            <text fg={t().muted}>{"↑↓ select · enter run · esc dismiss"}</text>
          </box>
        </box>
      </Show>

      <Show when={dialog() === "help"}>
        <HelpDialog onClose={() => setDialog(null)} />
      </Show>
      <Show when={dialog() === "themes"}>
        <ThemeDialog onClose={() => setDialog(null)} onApply={(name) => showToast(`theme: ${name}`)} />
      </Show>

      <Show when={toastMsg()}>
        <box position="absolute" bottom={8} right={1} backgroundColor={t().panel}>
          <box
            border
            borderColor={t().border}
            backgroundColor={t().panel}
            customBorderChars={ROUNDED_BORDER_CHARS}
            paddingLeft={1}
            paddingRight={1}
          >
            <text fg={t().accent}>{toastMsg()}</text>
          </box>
        </box>
      </Show>
    </box>
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  if (!PROVIDERS.includes(args.provider)) {
    process.stderr.write(`Unsupported --provider: ${args.provider} (expected ${PROVIDERS.join(", ")})\n`);
    process.exit(2);
  }

  const makeSession = (provider: string, apiKey: string) =>
    new ChatSession({
      provider,
      apiKey,
      model: args.model,
      defaultCwd: path.resolve(args.cwd),
      enableValidation: !!args.enableValidation,
      confirmFn: async () => false,
    });

  const bannerFor = (session: any) => {
    let banner = `MrRobotBot chat -- provider: ${session.provider}, default folder: ${session.defaultCwd}`;
    if (args.enableValidation) {
      banner += "\n⚠ validation tools enabled -- every http_request/run_command still asks to confirm first.";
    }
    return banner + "\nAsk me to scan, list findings, or explain one.";
  };

  // A missing key is no longer fatal: the TUI opens on the key screen and
  // swaps to the chat once one is entered. resolveApiKey still short-circuits
  // it entirely when --api-key or the env var is already set.
  const apiKey = resolveApiKey(args.provider, args.apiKey);

  function Root() {
    const [session, setSession] = createSignal<any>(apiKey ? makeSession(args.provider, apiKey) : null);
    return (
      <Show
        when={session()}
        fallback={
          <ApiKeyPrompt
            provider={args.provider}
            onSubmit={(provider, key) => setSession(makeSession(provider, key))}
          />
        }
      >
        <App session={session()} banner={bannerFor(session())} />
      </Show>
    );
  }

  render(() => <Root />);
}

// Only take over the terminal when this file is the entry point -- importing
// it (the test harness renders <App> directly) must not start a session.
if (import.meta.main) main();
