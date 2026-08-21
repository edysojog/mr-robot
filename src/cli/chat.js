#!/usr/bin/env node
// Node + Ink front-end for the interactive chat agent -- see chatCore.js for
// the actual tool implementations and agentic turn loop (shared with the
// Bun + OpenTUI front-end, chatOpentui.tsx). This file is just argv
// parsing, the Ink component tree, and process wiring.

const path = require('path');
const {
  dim,
  bold,
  green,
  red,
  ChatSession,
  resolveApiKey,
  setWriteOut,
} = require('./chatCore');

const HELP = `
MrRobotBot chat -- talk to the scanner instead of flagging it

Usage:
  mrrobotbot-chat [options]

Options:
  --provider <name>       claude | groq   (default: claude)
  --model <name>          Model override for the selected provider
  --api-key <key>         API key (or ANTHROPIC_API_KEY / GROQ_API_KEY env var)
  --cwd <path>            Default folder for scans when you don't name one (default: current directory)
  --enable-validation     Give the agent two extra tools: http_request (send one HTTP request against a
                          target you're running) and run_command (run one shell command on THIS machine)
                          to actually validate a finding instead of just reasoning about it in text. Off
                          by default. Every single use of either tool still stops and asks you to
                          confirm the exact request/command before it runs -- this flag only controls
                          whether the agent has the tools at all, not whether it needs your permission.
  --help                  Show this help

Once running, just talk to it in plain English:
  > scan this project
  > what's finding 3 about?
  > is finding 1 actually exploitable, or a false positive?
  > list only the critical findings
  > (with --enable-validation) prove finding 2 is really an unauthenticated endpoint
  /exit or ctrl+c to quit.

Note: the input box is a fixed pane at the bottom (arrow-key cursor movement
within the line is supported; up/down command history is not).
`;

function parseArgs(argv) {
  const args = { provider: 'claude', cwd: process.cwd() };
  const rest = [...argv];
  while (rest.length > 0) {
    const token = rest.shift();
    switch (token) {
      case '--provider': args.provider = rest.shift(); break;
      case '--model': args.model = rest.shift(); break;
      case '--api-key': args.apiKey = rest.shift(); break;
      case '--cwd': args.cwd = rest.shift(); break;
      case '--enable-validation': args.enableValidation = true; break;
      case '--help': case '-h': args.help = true; break;
      default: break;
    }
  }
  return args;
}

// Pinned-bottom input pane built on Ink -- the same React-for-CLIs renderer
// Claude Code itself is built on, rather than hand-rolled ANSI scroll
// regions (tried first; real rendering bugs showed up under a DECSTBM
// region on Windows Terminal, and Ink already solves this properly).
// `<Static>` renders each log entry exactly once and leaves it alone --
// that's the scrolling history -- while the bordered Box below it is Ink's
// normal (non-static) render output, which Ink keeps redrawing at the
// bottom of the terminal. Ink is ESM-only, so it's loaded via dynamic
// import() from this CommonJS file rather than require() -- react is
// loaded the same way so both resolve through the same ESM module cache
// Ink itself uses internally (mixing require('react') and import('ink')
// would load two separate React instances and break hooks).
async function runInk(session, bannerText) {
  const [{ default: React }, { render, Box, Text, Static, useApp }, { default: TextInput }] = await Promise.all([
    import('react'),
    import('ink'),
    import('ink-text-input'),
  ]);
  const h = React.createElement;

  function App() {
    const [logs, setLogs] = React.useState([]);
    const [value, setValue] = React.useState('');
    const [busy, setBusy] = React.useState(false);
    const [confirmState, setConfirmState] = React.useState(null); // { resolve } while a validation-tool confirm is pending
    const idRef = React.useRef(0);
    const { exit } = useApp();

    // kind: 'user' (gets the left accent bar, no label) | 'plain' (everything
    // else -- tool traces, finding cards, replies -- already colored by the
    // dim/green/red/etc helpers, printed as-is).
    const pushLog = React.useCallback((text, kind = 'plain') => {
      idRef.current += 1;
      setLogs((prev) => [...prev, { id: idRef.current, text, kind }]);
    }, []);

    React.useEffect(() => {
      // Redirect the module-level output sink and the session's confirm
      // gate into this component once it's mounted -- see writeOut's
      // definition near the top of this file for the default (plain
      // stdout) behavior this overrides.
      setWriteOut((text) => pushLog(text.replace(/\n+$/, '')));
      session.confirmFn = (message) =>
        new Promise((resolve) => {
          pushLog(message);
          setConfirmState({ resolve });
        });
      pushLog(bannerText);
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    async function handleSubmit(raw) {
      const text = raw.trim();
      setValue('');

      if (confirmState) {
        const approved = text.toLowerCase() === 'y';
        const resolve = confirmState.resolve;
        setConfirmState(null);
        pushLog(dim(approved ? 'confirmed.' : 'declined.'));
        resolve(approved);
        return;
      }

      if (!text) return;
      if (text === '/exit' || text === '/quit') { exit(); process.exit(0); }

      pushLog(text, 'user');
      setBusy(true);
      try {
        const reply = await session.turn(text);
        pushLog(reply);
      } catch (err) {
        pushLog(red(`error: ${err.message}`));
      }
      setBusy(false);
    }

    const modelLabel = `${session.provider}${session.model ? ' \u00b7 ' + session.model : ''}`;

    return h(
      Box,
      { flexDirection: 'column' },
      h(Static, { items: logs }, (item) =>
        item.kind === 'user'
          ? h(
              Box,
              { key: item.id, flexDirection: 'row', marginTop: 1, marginBottom: 1 },
              h(Text, { color: 'blue' }, '\u2503 '),
              h(Text, { bold: true }, item.text)
            )
          : h(Box, { key: item.id }, h(Text, null, item.text))
      ),
      h(
        Box,
        { flexDirection: 'column', marginTop: 1 },
        h(
          Box,
          { backgroundColor: confirmState ? 'yellow' : 'blackBright', paddingX: 1 },
          h(Text, { color: confirmState ? 'black' : 'blue', backgroundColor: confirmState ? 'yellow' : 'blackBright' }, confirmState ? 'confirm [y/N] ' : '\u203a '),
          busy
            ? h(Text, { dimColor: true, backgroundColor: 'blackBright' }, 'working\u2026')
            : h(TextInput, { value, onChange: setValue, onSubmit: handleSubmit })
        ),
        h(
          Box,
          { justifyContent: 'space-between' },
          h(Text, { dimColor: true }, modelLabel),
          h(Text, { dimColor: true }, 'ctrl+c quit')
        )
      )
    );
  }

  const { waitUntilExit } = render(h(App));
  await waitUntilExit();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  if (!['claude', 'groq'].includes(args.provider)) {
    process.stderr.write(`Unsupported --provider: ${args.provider} (expected claude or groq)\n`);
    process.exit(2);
  }

  const apiKey = resolveApiKey(args.provider, args.apiKey);
  if (!apiKey) {
    const envVar = args.provider === 'claude' ? 'ANTHROPIC_API_KEY' : 'GROQ_API_KEY';
    process.stderr.write(`No API key for provider "${args.provider}" -- pass --api-key or set ${envVar}\n`);
    process.exit(2);
  }

  if (!process.stdin.isTTY) {
    process.stderr.write('mrrobotbot-chat needs an interactive terminal (stdin is not a TTY).\n');
    process.exit(2);
  }

  const session = new ChatSession({
    provider: args.provider,
    apiKey,
    model: args.model,
    defaultCwd: path.resolve(args.cwd),
    enableValidation: !!args.enableValidation,
    // Overwritten by runInk once the Ink app mounts (see its useEffect) --
    // this default just means a confirm requested before mount fails safe.
    confirmFn: async () => false,
  });

  let banner = bold('MrRobotBot chat') + dim(` -- provider: ${args.provider}, default folder: ${session.defaultCwd}\n`);
  if (args.enableValidation) {
    banner += red('\u26a0 validation tools enabled') + dim(' -- the agent can send real HTTP requests and run real shell commands on this machine to validate a finding, but only after you confirm each one.\n');
  }
  banner += dim('Ask me to scan, list findings, or explain one.');

  await runInk(session, banner);
}

if (require.main === module) main();

module.exports = { ChatSession };
