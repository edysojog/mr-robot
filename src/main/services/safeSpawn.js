const { spawn, spawnSync } = require('child_process');

// Every external tool (semgrep, gitleaks, npm, git) is spawned through this
// instead of raw `spawn(..., { shell: true })`. The old blanket shell:true
// meant arguments were re-joined and re-parsed by a shell -- and those
// arguments include untrusted input, like file paths taken from a scanned
// repo's git diff. A repo containing a path with a space, `;` or backtick
// would break the command or execute under the scanning user.
//
// On POSIX we drop the shell entirely: argv-array spawn passes every
// argument verbatim as a single argv entry, so there is nothing to inject
// into.
//
// On Windows the shell stays, because pip/npm-installed console scripts are
// .cmd/.bat shims that only resolve through cmd.exe -- removing it breaks
// tool detection for everyone. Instead each argument is quoted per the
// MSVCRT argv rules, which keeps spaces/quotes/metacharacters (`&`, `|`,
// `>`) inside the argument boundary. Residual caveat: cmd.exe still expands
// %VAR% references even inside double quotes; paths containing literal %
// sequences remain a known gap on Windows.

function quoteWindowsArg(arg) {
  const str = String(arg);
  if (str !== '' && !/[\s"]/.test(str)) return str;

  let out = '"';
  let backslashes = 0;
  for (const ch of str) {
    if (ch === '\\') {
      backslashes += 1;
      continue;
    }
    if (ch === '"') {
      // Double the run of backslashes (they'd otherwise escape the quote)
      // plus one more to escape the quote itself.
      out += '\\'.repeat(backslashes * 2 + 1) + '"';
    } else {
      out += '\\'.repeat(backslashes) + ch;
    }
    backslashes = 0;
  }
  // Backslashes directly before the closing quote must be doubled too.
  out += '\\'.repeat(backslashes * 2);
  return `${out}"`;
}

function isWindows() {
  return process.platform === 'win32';
}

// Drop-in replacement for child_process.spawn. Returns the ChildProcess the
// caller already wires stdout/stderr/close handlers onto, so call sites only
// change their import.
function safeSpawn(cmd, args, options = {}) {
  if (!isWindows()) return spawn(cmd, args, options);
  return spawn(cmd, args.map(quoteWindowsArg), { ...options, shell: true });
}

function safeSpawnSync(cmd, args, options = {}) {
  if (!isWindows()) return spawnSync(cmd, args, options);
  return spawnSync(cmd, args.map(quoteWindowsArg), { ...options, shell: true });
}

module.exports = { safeSpawn, safeSpawnSync, quoteWindowsArg };
