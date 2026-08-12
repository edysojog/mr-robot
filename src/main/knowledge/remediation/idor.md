# Insecure Direct Object Reference (CWE-639)

**Root cause:** a request parameter (an ID in the URL, body, or query string) directly selects which resource to read/modify, with nothing stopping the caller from substituting a different ID they don't own.

**Fix pattern:** scope the lookup itself to the current user, rather than fetching by ID alone and hoping a check elsewhere catches it.

- Prefer building the ownership constraint into the query: `SELECT * FROM orders WHERE id = ? AND user_id = ?` (using the *authenticated* user's ID, not one from the request) instead of `SELECT * FROM orders WHERE id = ?` followed by a separate check.
- If an ORM is in use, scope through the user's own association (`currentUser.orders.find(id)`) rather than a bare model lookup (`Order.find(id)`).
- Don't rely on IDs being hard to guess (UUIDs) as the actual control — that raises the bar but isn't authorization; an explicit ownership check is still required.
- This overlaps with CWE-862/863 (broken authorization) — if the codebase already has an authorization-check pattern for other resources, apply the same one here instead of a bespoke ID comparison.
