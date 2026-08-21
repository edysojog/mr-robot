const { spawn } = require('child_process');

const ATTEMPT_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutes per package-manager attempt

// Runs one candidate install command. A missing package manager (command not
// on PATH) and a real install failure both surface as a non-zero/negative
// code here -- there's no reliable cross-platform way to tell them apart
// up front, so callers just move on to the next candidate either way.
function run(cmd, args) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { shell: true });
    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      resolve({ code: -1, stdout, stderr: stderr + '\n(timed out)' });
    }, ATTEMPT_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: stderr || err.message });
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

// Tries each candidate package manager in order, stopping at the first one
// that succeeds (exit code 0). Returns a log of every attempt either way, so
// the UI can show the user what was tried if all of them fail.
async function tryInstallers(candidates) {
  const attempts = [];
  for (const { cmd, args, label } of candidates) {
    const result = await run(cmd, args);
    attempts.push({ label, code: result.code, output: (result.stdout + result.stderr).trim().slice(-2000) });
    if (result.code === 0) {
      return { success: true, method: label, attempts };
    }
  }
  return { success: false, attempts };
}

// No --user here on purpose: on Windows, `pip install --user` puts the
// semgrep.exe console script under %APPDATA%\Python\PythonXY\Scripts, which
// nothing adds to PATH -- the install silently "succeeds" but the command
// stays unrunnable. A plain `pip install` targets the interpreter's own
// site-packages/Scripts, which for a per-user Python install (the default
// python.org installer option, installed under %LOCALAPPDATA%) is already
// on PATH and needs no elevation. If pip lacks write access here (e.g. an
// admin-installed system Python), this candidate just fails and the next
// one is tried.
function installSemgrep() {
  return tryInstallers([
    { cmd: 'pip', args: ['install', 'semgrep'], label: 'pip' },
    { cmd: 'pip3', args: ['install', 'semgrep'], label: 'pip3' },
    { cmd: 'python', args: ['-m', 'pip', 'install', 'semgrep'], label: 'python -m pip' },
  ]);
}

function installGitleaks() {
  return tryInstallers([
    { cmd: 'winget', args: ['install', '--id', 'Gitleaks.Gitleaks', '-e', '--accept-source-agreements', '--accept-package-agreements'], label: 'winget' },
    { cmd: 'choco', args: ['install', 'gitleaks', '-y'], label: 'choco' },
    { cmd: 'scoop', args: ['install', 'gitleaks'], label: 'scoop' },
    { cmd: 'brew', args: ['install', 'gitleaks'], label: 'brew' },
  ]);
}

// npm audit ships with Node.js itself -- "npm not found" means Node isn't
// installed, so this installs Node via a system package manager rather than
// npm directly.
function installNpm() {
  return tryInstallers([
    { cmd: 'winget', args: ['install', '--id', 'OpenJS.NodeJS.LTS', '-e', '--accept-source-agreements', '--accept-package-agreements'], label: 'winget' },
    { cmd: 'brew', args: ['install', 'node'], label: 'brew' },
  ]);
}

function installTool(tool) {
  if (tool === 'semgrep') return installSemgrep();
  if (tool === 'gitleaks') return installGitleaks();
  if (tool === 'npm') return installNpm();
  throw new Error(`Unknown tool: ${tool}`);
}

module.exports = { installTool, installSemgrep, installGitleaks, installNpm };
