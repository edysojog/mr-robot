// Bun + OpenTUI + SolidJS front-end -- the actual stack opencode's own TUI
// (packages/tui) is built on, rather than an ANSI approximation of its look.
// Shares ChatSession and the tool logic with the Node + Ink front-end
// (chat.js) via chatCore.js, required here through Bun's CJS interop (Bun
// supports require() from a .tsx entry same as any other module). Run with
// `bun run src/cli/chatOpentui.tsx` -- plain Node cannot run this file,
// OpenTUI's native renderer only initializes under Bun/Deno.

import { render, useKeyboard, useRenderer, useTerminalDimensions } from "@opentui/solid";
import { createSignal, For, onCleanup, onMount, Show } from "solid-js";

const path = require("path");
const coreModule = require("./chatCore");
const { ChatSession, resolveApiKey, setWriteOut } = coreModule;

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

const HELP = `
MrRobotBot chat (OpenTUI) -- opencode-style terminal UI, Bun-only

Usage:
  bun run src/cli/chatOpentui.tsx [options]

Options:
  --provider <name>       claude | groq   (default: claude)
  --model <name>          Model override for the selected provider
  --api-key <key>         API key (or ANTHROPIC_API_KEY / GROQ_API_KEY env var)
  --cwd <path>            Default folder for scans when you don't name one
  --enable-validation     Adds http_request/run_command tools -- every use still asks to confirm first
  --help                  Show this help
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

type LogKind =
  | "user"        // what you typed -- blue bar, no dot
  | "assistant"   // the model's reply -- green dot
  | "tool"        // a tool about to run -- blue dot
  | "tool-result" // that tool's output -- indented elbow
  | "log"         // incidental progress chatter -- indented, dim, no marker
  | "plain";      // banner and other UI text -- no marker

// `pending` is true for a tool row whose work is still in flight; it drives
// whether the gutter shows the spinner or the settled per-tool icon.
// `tool` is the tool's name, used to pick that icon.
type LogItem = { id: number; text: string; kind: LogKind; pending?: boolean; tool?: string };

// Green phosphor palette -- one place to retune the whole TUI.
const COLOR_TEXT = "#c8facc";    // body text: pale green, kept light enough to read as prose
const COLOR_ACCENT = "#39d353";  // icons, the user-message bar, the prompt caret
const COLOR_MUTED = "#5c9c6b";   // tool output and status chrome, recedes behind body text
const COLOR_PANEL = "#0d1710";   // near-black with a green cast, for filled panels
// The composer's outline in opencode is barely there -- the panel reads as a
// panel because of its fill, not its edge. A bright edge (the accent) turns it
// into the loudest thing on screen, so the border gets its own dim tone.
const COLOR_BORDER = "#1f3a26";
// The wordmark's drop shadow. Dark enough to read as depth behind the letters
// rather than as a second, blurrier wordmark competing with the first.
const COLOR_SHADOW = "#20502e";
// Cells with no ink still need a color for the half-block renderer; the panel
// tone doubles as "nothing here".
const COLOR_NONE = COLOR_PANEL;
// The confirm prompt gates real HTTP requests and shell commands, so it
// stays visually loud -- inverted (dark text on bright green) rather than
// another shade in the same range, which would make it easy to miss.
const COLOR_CONFIRM_BG = "#39d353";
const COLOR_CONFIRM_FG = "#04170a";

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
// Kept small deliberately -- 5 pixels wide by 6 tall, so three text rows.
// A diagonal drawn across ten rows has to step, and those steps are the
// staircase; at this size every stroke is either a full column or a single
// half-block, so the M's inner peak resolves to one ▀ and the O's corners to
// one ▄/▀ each. Nothing has room to staircase.
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

type Span = { text: string; fg: string; bg?: string };

// One text row = two pixel rows. A cell whose halves carry different inks
// becomes ▀ with the lower ink as its background; matching halves collapse to
// a solid █. Runs of identical (char, fg, bg) are merged so a row emits a
// handful of spans instead of one per column.
function wordmarkRowSpans(grid: number[][], textRow: number, inkColor: (ink: number) => string): Span[] {
  const top = grid[textRow * 2];
  const bottom = grid[textRow * 2 + 1];
  const spans: Span[] = [];
  for (let c = 0; c < top.length; c += 1) {
    const t = top[c];
    const b = bottom[c];
    let cell: Span;
    if (t === INK_NONE && b === INK_NONE) cell = { text: " ", fg: inkColor(INK_NONE) };
    else if (t === b) cell = { text: "█", fg: inkColor(t) };
    else if (b === INK_NONE) cell = { text: "▀", fg: inkColor(t) };
    else if (t === INK_NONE) cell = { text: "▄", fg: inkColor(b) };
    else cell = { text: "▀", fg: inkColor(t), bg: inkColor(b) };

    const prev = spans[spans.length - 1];
    if (prev && prev.text[0] === cell.text && prev.fg === cell.fg && prev.bg === cell.bg) {
      prev.text += cell.text;
    } else {
      spans.push(cell);
    }
  }
  return spans;
}

// Phrased as things to type, not slash commands -- the only slash commands
// this front-end actually handles are /exit and /quit, and listing anything
// else here would be inventing a command surface that does not exist.
const SPLASH_HINTS: [string, string][] = [
  ["scan this folder", "run the full scan pipeline"],
  ["what did you find", "list findings from the last scan"],
  ["explain finding 3", "dig into one finding"],
  ["/exit", "quit the session"],
];
const INK_COLORS: Record<number, string> = {
  [INK_NONE]: COLOR_NONE,
  [INK_DIM]: COLOR_MUTED,
  [INK_BRIGHT]: COLOR_ACCENT,
  [INK_SHADOW]: COLOR_SHADOW,
};
const WORDMARK_ROWS: Span[][] = Array.from(
  { length: WORDMARK_GRID.length / 2 },
  (_, row) => wordmarkRowSpans(WORDMARK_GRID, row, (ink) => INK_COLORS[ink])
);

const HINT_COLUMN = 20;
const HINT_WIDTH = HINT_COLUMN + Math.max(...SPLASH_HINTS.map(([, desc]) => desc.length));

// The banner block above the conversation: wordmark, then the session's
// provider/folder line, then the hints. Lives inside the scrollbox so it
// scrolls away as the conversation grows rather than pinning to the top.
function Splash(props: { banner: string }) {
  // The wordmark is a fixed 69 columns and cannot reflow. Centered in a
  // narrower terminal it gets clipped at *both* ends -- losing the M and the
  // T -- so below its width it drops to a plain-text title instead.
  const dims = useTerminalDimensions();
  const roomForWordmark = () => dims().width >= LOGO_WIDTH + 4;
  // The hint rows are a fixed-width two-column block and clip the same way
  // the wordmark does -- at both ends, since they are centered. There is no
  // useful narrow rendering of them, so they just drop out.
  const roomForHints = () => dims().width >= HINT_WIDTH + 4;

  // alignItems="center" centers each child on its own natural width, so the
  // wordmark, the banner line and the hint block each get centered as a
  // unit -- while the hint rows stay left-aligned *within* that block, which
  // is what keeps their two columns lined up with each other.
  return (
    <box flexDirection="column" alignItems="center" marginTop={1} marginBottom={1} flexShrink={0}>
      {roomForWordmark() ? (
        <box flexDirection="column" flexShrink={0}>
          <For each={WORDMARK_ROWS}>
            {(spans) => (
              <box flexDirection="row">
                <For each={spans}>
                  {(span) => <text fg={span.fg} bg={span.bg}>{span.text}</text>}
                </For>
              </box>
            )}
          </For>
          {/* Version sits under the wordmark's right edge, as opencode's does. */}
          <box width={LOGO_WIDTH} flexShrink={0} justifyContent="flex-end" flexDirection="row">
            <text fg={COLOR_MUTED}>{VERSION}</text>
          </box>
        </box>
      ) : (
        <box flexDirection="row" flexShrink={0}>
          <text fg={COLOR_MUTED}>MR</text>
          <text fg={COLOR_ACCENT}>ROBOT </text>
          <text fg={COLOR_MUTED}>{VERSION}</text>
        </box>
      )}
      <box marginTop={1} flexShrink={0}>
        <text fg={COLOR_MUTED}>{props.banner}</text>
      </box>
      <Show when={roomForHints()}>
        <box flexDirection="column" marginTop={1} flexShrink={0}>
          <For each={SPLASH_HINTS}>
            {([cmd, desc]) => (
              <box flexDirection="row">
                <text width={HINT_COLUMN} flexShrink={0} fg={COLOR_TEXT}>{cmd}</text>
                <text fg={COLOR_MUTED}>{desc}</text>
              </box>
            )}
          </For>
        </box>
      </Show>
    </box>
  );
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

// One entry in the scrollback, following opencode's InlineTool structure:
// a 2-cell icon column with the body beside it, so a wrapped body stays
// aligned under itself rather than sliding back under the icon.
function LogRow(props: { item: LogItem; spinner: () => string }) {
  const kind = () => props.item.kind;

  // User message: a heavy left bar with a filled panel beside it, drawn
  // as a left-only border the way opencode's UserMessage does, rather
  // than a bar character glued onto the text.
  if (kind() === "user") {
    return (
      <box
        border={["left"]}
        borderColor={COLOR_ACCENT}
        customBorderChars={SPLIT_BORDER_CHARS}
        marginTop={1}
        marginBottom={1}
        flexShrink={0}
      >
        <box paddingTop={1} paddingBottom={1} paddingLeft={2} backgroundColor={COLOR_PANEL} flexShrink={0}>
          <text fg={COLOR_TEXT}>{props.item.text}</text>
        </box>
      </box>
    );
  }

  // Assistant replies carry no icon at all in opencode -- they're just
  // body text, which is what keeps the icon column meaningful.
  if (kind() === "assistant" || kind() === "plain") {
    return (
      <box marginTop={kind() === "assistant" ? 1 : 0}>
        <text fg={COLOR_TEXT}>{props.item.text}</text>
      </box>
    );
  }

  // Tool output and progress chatter both hang under the icon column.
  if (kind() === "tool-result" || kind() === "log") {
    return (
      <box paddingLeft={TOOL_ICON_WIDTH}>
        <text fg={COLOR_MUTED}>{props.item.text}</text>
      </box>
    );
  }

  // A tool: spinner while it runs, its own icon once settled.
  return (
    <box flexDirection="row" marginTop={1}>
      <text width={TOOL_ICON_WIDTH} flexShrink={0} fg={COLOR_ACCENT}>
        {props.item.pending ? props.spinner() : (TOOL_ICON[props.item.tool ?? ""] ?? TOOL_ICON_FALLBACK)}
      </text>
      <text flexGrow={1} fg={COLOR_TEXT}>{props.item.text}</text>
    </box>
  );
}

export function App(props: { session: any; banner: string }) {
  const [logs, setLogs] = createSignal<LogItem[]>([]);
  const [value, setValue] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  // Holds the pending confirm() resolver while a validation-tool call is
  // waiting on a y/n answer -- non-null means the input line is currently
  // acting as that confirm prompt instead of the normal chat box.
  const [confirmResolve, setConfirmResolve] = createSignal<((v: boolean) => void) | null>(null);
  const spinner = createSpinner();
  watchTerminalSize();
  let idCounter = 0;
  let inputRef: any;

  // Marks every currently-spinning row as settled. Called when a tool
  // reports its result, and again when a turn ends -- the second call
  // matters because some tools render no result at all (renderToolResult
  // returns '' and the row is skipped), which would otherwise leave a row
  // spinning forever.
  function settlePending() {
    setLogs((prev) =>
      prev.some((l) => l.pending) ? prev.map((l) => (l.pending ? { ...l, pending: false } : l)) : prev
    );
  }

  function pushLog(text: string, kind: LogKind = "plain", meta?: { tool?: string }) {
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
    setLogs((prev) => [
      ...prev,
      { id: idCounter, text: clean, kind, pending: kind === "tool", tool: meta?.tool },
    ]);
  }

  onMount(() => {
    // chatCore tags each write with its kind ('tool' | 'tool-result' |
    // 'log'); anything untagged is plain UI text.
    setWriteOut((text: string, kind: LogKind = "plain", meta?: { tool?: string }) => pushLog(text, kind, meta));
    props.session.confirmFn = (message: string) =>
      new Promise<boolean>((resolve) => {
        pushLog(message);
        setConfirmResolve(() => resolve);
      });
    // The banner is rendered by <Splash>, not pushed as a log row.
    inputRef?.focus?.();
  });

  useKeyboard((key: any) => {
    if (key.ctrl && key.name === "c") process.exit(0);
  });

  async function handleSubmit(raw: string) {
    const text = raw.trim();
    setValue("");

    const resolve = confirmResolve();
    if (resolve) {
      const approved = text.toLowerCase() === "y";
      setConfirmResolve(null);
      pushLog(approved ? "confirmed." : "declined.");
      resolve(approved);
      return;
    }

    // The input stays mounted even while busy (see the JSX below) so it
    // never loses focus mid-conversation -- this guard is what actually
    // stops a second turn from starting if Enter is pressed while one is
    // already running.
    if (busy()) return;

    if (!text) return;
    if (text === "/exit" || text === "/quit") process.exit(0);

    pushLog(text, "user");
    setBusy(true);
    try {
      const reply = await props.session.turn(text);
      settlePending();
      pushLog(reply, "assistant");
    } catch (err: any) {
      settlePending();
      pushLog(`error: ${err.message}`, "assistant");
    }
    setBusy(false);
  }

  const modelLabel = () => `${props.session.provider}${props.session.model ? " · " + props.session.model : ""}`;
  const confirming = () => confirmResolve() !== null;

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
        when={logs().length > 0}
        fallback={
          <box flexGrow={1} justifyContent="center" alignItems="center">
            <Splash banner={props.banner} />
          </box>
        }
      >
        <scrollbox flexGrow={1} stickyScroll stickyStart="bottom" paddingX={1}>
          <Splash banner={props.banner} />
          <For each={logs()}>
            {(item) => <LogRow item={item} spinner={spinner} />}
          </For>
        </scrollbox>
      </Show>

      {/*
        flexShrink={0} keeps the taller composer whole: the scrollbox above
        has flexGrow={1}, so without it yoga trims these rows to fit and the
        status line under the box is the first thing to disappear.
      */}
      <box flexDirection="column" marginTop={1} paddingX={1} flexShrink={0}>
        {/*
          A filled panel closed on all four sides in the dim border tone. The
          left edge used to carry a bright accent bar (opencode's treatment,
          which their user messages still use here) -- dropped, so the only
          thing that lights up down there is the confirm prompt.
          Three rows tall in total.
        */}
        <box
          border
          borderColor={confirming() ? COLOR_CONFIRM_BG : COLOR_BORDER}
          backgroundColor={confirming() ? COLOR_CONFIRM_BG : COLOR_PANEL}
          paddingLeft={1}
          paddingRight={1}
          flexGrow={1}
          flexDirection="row"
          flexShrink={0}
        >
          <text
            fg={confirming() ? COLOR_CONFIRM_FG : COLOR_ACCENT}
            bg={confirming() ? COLOR_CONFIRM_BG : COLOR_PANEL}
          >
            {confirming() ? "confirm [y/N] " : "› "}
          </text>
          {/*
            flexGrow is load-bearing, not cosmetic: with the input at its
            default auto width it gets laid out overlapping the prompt to
            its left, and the first N characters typed are clipped -- N
            being the prompt's width, so "› " ate exactly two. Verified with
            captureCharFrame(): auto width renders "› llo" for typed
            "hello", flexGrow={1} renders "› hello".
          */}
          <input
            ref={(el: any) => { inputRef = el; }}
            flexGrow={1}
            value={value()}
            focused={true}
            fg={confirming() ? COLOR_CONFIRM_FG : COLOR_TEXT}
            bg={confirming() ? COLOR_CONFIRM_BG : COLOR_PANEL}
            onInput={setValue}
            onSubmit={handleSubmit}
          />
          {busy() ? (
            <text fg={COLOR_MUTED} bg={COLOR_PANEL}>{`  ${spinner()} working…`}</text>
          ) : null}
        </box>
        {/*
          opencode puts the keybind hint on the left and the model on the
          right, under the box rather than above it -- the reverse of what
          was here.
        */}
        <box flexDirection="row" justifyContent="space-between" paddingLeft={1}>
          <text fg={COLOR_MUTED}>enter send · ctrl+c quit</text>
          <text fg={COLOR_MUTED}>{modelLabel()}</text>
        </box>
      </box>
    </box>
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  if (!["claude", "groq"].includes(args.provider)) {
    process.stderr.write(`Unsupported --provider: ${args.provider} (expected claude or groq)\n`);
    process.exit(2);
  }

  const apiKey = resolveApiKey(args.provider, args.apiKey);
  if (!apiKey) {
    const envVar = args.provider === "claude" ? "ANTHROPIC_API_KEY" : "GROQ_API_KEY";
    process.stderr.write(`No API key for provider "${args.provider}" -- pass --api-key or set ${envVar}\n`);
    process.exit(2);
  }

  const session = new ChatSession({
    provider: args.provider,
    apiKey,
    model: args.model,
    defaultCwd: path.resolve(args.cwd),
    enableValidation: !!args.enableValidation,
    confirmFn: async () => false,
  });

  let banner = `MrRobotBot chat -- provider: ${args.provider}, default folder: ${session.defaultCwd}`;
  if (args.enableValidation) {
    banner += "\n⚠ validation tools enabled -- every http_request/run_command still asks to confirm first.";
  }
  banner += "\nAsk me to scan, list findings, or explain one.";

  render(() => <App session={session} banner={banner} />);
}

// Only take over the terminal when this file is the entry point -- importing
// it (the test harness renders <App> directly) must not start a session.
if (import.meta.main) main();
