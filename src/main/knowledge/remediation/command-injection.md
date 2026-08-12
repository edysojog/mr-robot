# OS Command Injection (CWE-78)

**Root cause:** untrusted input reaches a shell interpreter, where it can inject additional commands via `; | & $() \`\` \n`.

**Fix pattern:** avoid the shell entirely — call the target program directly with an argument array, so the OS never re-parses a command string.

- Node: use `child_process.execFile(cmd, [arg1, arg2])` or `spawn(cmd, args)` instead of `exec()`/`spawn(cmd, { shell: true })`. If `exec()` must stay, never interpolate user input into the command string.
- Python: use `subprocess.run([cmd, arg1, arg2], shell=False)` instead of `subprocess.run(cmd_string, shell=True)` or `os.system()`.
- Ruby: use `system(cmd, arg1, arg2)` (array form) instead of `` `#{cmd} #{arg}` `` backticks or a single interpolated string.
- Java: use `ProcessBuilder(cmd, arg1, arg2)` instead of `Runtime.exec(String)`.

If a shell feature (pipes, globbing) is genuinely required, validate the input against a strict allowlist (e.g. `^[a-zA-Z0-9_-]+$`) before it reaches the shell — don't rely on blocklisting metacharacters, it's easy to miss one.
