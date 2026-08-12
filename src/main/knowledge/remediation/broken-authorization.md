# Missing or Incorrect Authorization (CWE-862, CWE-863)

**Root cause:** the caller is authenticated, but the code doesn't check whether *this* caller is allowed to act on *this* specific resource/action — often a resource ID taken straight from the request and used to fetch/modify data with no ownership or role check.

**Fix pattern:** add an explicit check, right before the resource is read/written, that the current user owns it or holds the required role — don't rely on the resource being "hard to guess" (that's CWE-639/IDOR territory, and isn't authorization).

- Typical shape: `if (resource.ownerId !== currentUser.id) return res.status(403).end();` (or the equivalent role check: `if (!currentUser.roles.includes('admin')) ...`) inserted after the resource is loaded and before it's used.
- Prefer checking at the data-access layer (e.g. `WHERE id = ? AND owner_id = ?` in the query itself) over a middleware-only check, so the authorization can't be bypassed by a code path that skips the middleware.
- For function-level authorization (an admin-only action reachable by a regular user), the check is on the *action*, not a specific resource — verify role/permission before executing, not after.
- If a permission system (RBAC/ABAC library) already exists in the codebase, use it rather than a one-off `if` check, for consistency with the rest of the app.
