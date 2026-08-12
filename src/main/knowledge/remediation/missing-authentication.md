# Missing Authentication for Critical Function (CWE-306)

**Root cause:** an endpoint or action performs a sensitive operation without first verifying who's calling it, while comparable endpoints elsewhere in the codebase do check.

**Fix pattern:** add the same authentication check used by sibling endpoints — look at how an adjacent route/handler in the same file or router verifies identity (middleware, decorator, guard clause) and apply the identical mechanism here, rather than inventing a new one.

- Express/Koa/Fastify: add the existing auth middleware (`requireAuth`, `passport.authenticate`, JWT-verify middleware) to this route's chain.
- Django/Flask: add the existing `@login_required`/`@permission_required` decorator or DRF permission class.
- Spring: add the missing `@PreAuthorize`/security-config rule matching this endpoint's peers.
- If there genuinely is no existing pattern to reuse, the minimal fix is: verify a valid session/token is present before the handler body runs, and reject (401/403) otherwise — don't add authorization/role logic here, that's a separate concern (see CWE-862/863).
