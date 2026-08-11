const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

function runGit(rootDir, args) {
  return new Promise((resolve) => {
    const child = spawn('git', args, { cwd: rootDir, shell: true });
    let stdout = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.on('error', () => resolve({ ok: false, stdout: '' }));
    child.on('close', (code) => resolve({ ok: code === 0, stdout }));
  });
}

async function isGitRepo(rootDir) {
  const result = await runGit(rootDir, ['rev-parse', '--is-inside-work-tree']);
  return result.ok && result.stdout.trim() === 'true';
}

function parseLines(stdout) {
  return stdout.split('\n').map((l) => l.trim()).filter(Boolean);
}

// Relative paths (rootDir-relative, forward-slash) of files with any working
// tree or staged changes vs HEAD, plus untracked new files. Deletions are
// excluded since there's no content left to scan.
async function getChangedFiles(rootDir) {
  const [diffResult, untrackedResult] = await Promise.all([
    runGit(rootDir, ['diff', '--name-only', 'HEAD']),
    runGit(rootDir, ['ls-files', '--others', '--exclude-standard']),
  ]);

  const candidates = new Set([
    ...(diffResult.ok ? parseLines(diffResult.stdout) : []),
    ...(untrackedResult.ok ? parseLines(untrackedResult.stdout) : []),
  ]);

  const existing = [];
  for (const relPath of candidates) {
    const absPath = path.join(rootDir, relPath);
    if (fs.existsSync(absPath) && fs.statSync(absPath).isFile()) {
      existing.push(relPath.split(path.sep).join('/'));
    }
  }
  return existing;
}

module.exports = { isGitRepo, getChangedFiles };
