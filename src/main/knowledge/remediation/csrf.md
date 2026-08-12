# Cross-Site Request Forgery (CWE-352)

**Root cause:** a state-changing endpoint (POST/PUT/DELETE that writes data or triggers an action) accepts requests based on ambient credentials (cookies) alone, so another site can trigger it via the victim's browser.

**Fix pattern:** verify the request actually originated from your own app, not just that the browser attached a valid session cookie.

- Framework-provided CSRF middleware is the default fix if the codebase already has one available/configured elsewhere (Django's `CsrfViewMiddleware`, Rails' `protect_from_forgery`, `csurf`/`csrf-csrf` for Express) — enable/apply it to this route rather than hand-rolling a token check.
- If cookies are the session mechanism, set `SameSite=Lax` or `Strict` on the session cookie as a strong baseline defense, in addition to (not instead of) a token check for state-changing routes.
- For token-auth APIs (Authorization header, not cookies) CSRF doesn't apply the same way, since the token isn't sent automatically by the browser — don't add a CSRF token there, note that the actual mechanism already prevents it.
- Never "fix" this by only checking the `Referer`/`Origin` header — it's a reasonable additional check but not sufficient on its own.
