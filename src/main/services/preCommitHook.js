const fs = require('fs');
const path = require('path');

const MARKER = '# Installed by MrRobotBot -- do not hand-edit, reinstall/uninstall via the app';

function cliPath() {
  return path.join(__dirname, '..', '..', 'cli', 'index.js');
}

function hookPath(rootDir) {
  return path.join(rootDir, '.git', 'hooks', 'pre-commit');
}

function status(rootDir) {
  const hp = hookPath(rootDir);
  if (!fs.existsSync(hp)) return 'not-installed';
  const content = fs.readFileSync(hp, 'utf8');
  return content.includes(MARKER) ? 'installed' : 'foreign';
}

function buildScript() {
  // Runs only the fast, free, deterministic Semgrep pass in diff mode --
  // no API key, no per-commit cost or latency from an AI call. Deeper
  // AI-assisted audits stay a manual action in the app/CLI.
  //
  // Invokes Electron's own bundled Node runtime (ELECTRON_RUN_AS_NODE=1)
  // rather than a bare `node` on PATH -- git hooks run in a minimal shell
  // environment that doesn't reliably inherit PATH, and this also makes
  // the packaged app self-contained (no separate Node.js install required).
  const electronPath = process.execPath.replace(/\\/g, '/');
  const script = `#!/bin/sh
${MARKER}
ELECTRON_RUN_AS_NODE=1 "${electronPath}" "${cliPath().replace(/\\/g, '/')}" "$(git rev-parse --show-toplevel)" --diff --semgrep-only --fail-on high
exit $?
`;
  return script;
}

function install(rootDir) {
  const current = status(rootDir);
  if (current === 'foreign') {
    throw new Error('An existing pre-commit hook was found that MrRobotBot did not install -- remove or back it up manually first.');
  }
  const hooksDir = path.join(rootDir, '.git', 'hooks');
  if (!fs.existsSync(hooksDir)) {
    throw new Error(`${rootDir} does not look like a git repository (no .git/hooks directory).`);
  }
  fs.writeFileSync(hookPath(rootDir), buildScript(), { mode: 0o755 });
  fs.chmodSync(hookPath(rootDir), 0o755); // fs.writeFileSync's mode is ignored on some platforms if the file already existed
  return 'installed';
}

function uninstall(rootDir) {
  const current = status(rootDir);
  if (current === 'not-installed') return 'not-installed';
  if (current === 'foreign') {
    throw new Error('The existing pre-commit hook was not installed by MrRobotBot -- refusing to remove it.');
  }
  fs.unlinkSync(hookPath(rootDir));
  return 'not-installed';
}

module.exports = { status, install, uninstall };
