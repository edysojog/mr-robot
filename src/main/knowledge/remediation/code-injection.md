# Code Injection (CWE-94)

**Root cause:** untrusted input reaches a function that compiles/executes it as code — `eval`, `Function()`, `exec`/`compile` in Python, `vm.runInContext`, or deserializing a format that can construct arbitrary objects/callables.

**Fix pattern:** eliminate the dynamic-execution path rather than trying to sandbox untrusted input.

- Replace `eval(expr)` / `new Function(body)` with a real parser for the specific thing being evaluated (e.g. a JSON parser for data, a small expression-language library for formulas) — never a general-purpose interpreter fed user input.
- Replace `exec()`/`compile()` on user-controlled Python source the same way — if the goal is configurable behavior, use data (JSON/YAML with a fixed schema) plus a dispatch table, not executable code.
- If templating (Jinja2, Handlebars, EJS) is being used to render user-supplied *templates* (not just variables into a fixed template), that's server-side template injection — use a sandboxed template environment or, better, don't let users author templates at all.
- If dynamic dispatch is the actual need (e.g. "call one of these N functions by name"), use an explicit allowlist map from name → function, not `getattr`/`globals()[name]`/`window[name]` on unchecked input.
