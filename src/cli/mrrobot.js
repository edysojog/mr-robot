#!/usr/bin/env node
// Single entry point: `mrrobot <subcommand>`, so the three ways to run this
// project stop being three different `npm run` invocations.
//
// Deliberately a dispatcher, not a rewrite -- it forwards to the existing
// entry points where they already live. src/cli/index.js in particular is
// referenced by absolute path from preCommitHook.js, which writes a hook
// script into .git/hooks on the user's machine; hooks already installed out
// there do not update themselves, so moving that file would break them.
//
// Plain node with a shebang, on purpose: npm generates the Windows .cmd/.ps1
// shims from it, and those read the shebang to pick a runtime. A bun-only or
// .tsx dispatcher would not shim.

const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');
const { safeSpawnSync } = require('../main/services/safeSpawn');

const REPO_ROOT = path.join(__dirname, '..', '..');
const IS_WINDOWS = process.platform === 'win32';

const HELP = `
MrRobotBot -- local security auditor

Usage:
  mrrobot <command> [options]

Commands:
  audit <folder>   Headless scan -- no UI. Semgrep/Gitleaks/npm audit plus an
                   optional AI pass. Exits 1 when something at or above
                   --fail-on is found, so it can gate a hook or CI.
  code             Interactive chat agent in the terminal. Talk to it in plain
                   English; it decides when to scan, list or explain.
  app              The desktop app.

Run a command with --help for its own options, e.g. mrrobot audit --help
`;

// Locating bun cannot rely on PATH alone. bun's installer drops it in
// ~/.bun/bin, which plenty of shells (and every non-login process that
// inherits a stale environment) do not have -- and a miss here would silently
// downgrade to the Ink front-end, which looks like the OpenTUI one is broken.
function findBun() {
  const exe = IS_WINDOWS ? 'bun.exe' : 'bun';
  const home = process.env.USERPROFILE || process.env.HOME || '';
  const candidates = [
    process.env.BUN_INSTALL && path.join(process.env.BUN_INSTALL, 'bin', exe),
    home && path.join(home, '.bun', 'bin', exe),
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  // Fall back to whatever PATH resolves, but only if it actually runs.
  const probe = safeSpawnSync('bun', ['--version'], { stdio: 'ignore' });
  return probe.status === 0 ? 'bun' : null;
}

function forwardExit(result) {
  if (result.error) {
    process.stderr.write(`mrrobot: ${result.error.message}\n`);
    process.exit(1);
  }
  // Preserve the child's exit code -- `audit` returning 1 on --fail-on is the
  // whole reason the CI gate and the pre-commit hook work.
  if (result.signal) process.exit(1);
  process.exit(result.status === null ? 1 : result.status);
}

function runAudit(args) {
  // Run in-process rather than spawning: index.js calls process.exit() itself,
  // so its exit codes propagate with no plumbing at all.
  process.argv = [process.argv[0], path.join(__dirname, 'index.js'), ...args];
  require('./index.js');
}

function runCode(args) {
  const bun = findBun();
  if (bun) {
    forwardExit(spawnSync(bun, ['run', path.join(__dirname, 'chatOpentui.tsx'), ...args], {
      stdio: 'inherit',
      cwd: REPO_ROOT,
    }));
  }
  // Never downgrade silently -- say which front-end is running and why.
  process.stderr.write('mrrobot: bun not found, falling back to the Ink front-end.\n');
  process.stderr.write('mrrobot: install bun (https://bun.sh) for the full terminal UI.\n');
  forwardExit(spawnSync(process.execPath, [path.join(__dirname, 'chat.js'), ...args], {
    stdio: 'inherit',
    cwd: REPO_ROOT,
  }));
}

function runApp(args) {
  let electron;
  try {
    electron = require('electron'); // exports the binary path when required from node
  } catch {
    process.stderr.write('mrrobot: electron is not installed -- run npm install first.\n');
    process.exit(1);
  }
  forwardExit(spawnSync(electron, [REPO_ROOT, ...args], { stdio: 'inherit', cwd: REPO_ROOT }));
}

// argv[2] is the subcommand; everything after it belongs to that subcommand
// and is forwarded untouched. No flag parsing here, so `mrrobot audit --help`
// reaches index.js's own help rather than being intercepted.
const command = process.argv[2];
const rest = process.argv.slice(3);

switch (command) {
  case 'audit': runAudit(rest); break;
  case 'code': runCode(rest); break;
  case 'app': runApp(rest); break;
  case undefined:
  case 'help':
  case '--help':
  case '-h':
    process.stdout.write(HELP);
    process.exit(0);
    break;
  default:
    process.stderr.write(`mrrobot: unknown command "${command}"\n${HELP}`);
    process.exit(2);
}
