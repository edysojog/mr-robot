# Server-Side Request Forgery (CWE-918)

**Root cause:** the server makes an outbound HTTP/network request to a URL (or host/port) derived from user input, letting an attacker make the server reach internal-only services (cloud metadata endpoints, internal APIs, localhost).

**Fix pattern:** validate the destination *after* DNS resolution, against an allowlist, not just the string the user typed.

- Prefer an allowlist of permitted hosts/domains for the specific feature (e.g. "only fetch from these known image CDNs") over trying to blocklist internal ranges — blocklists miss cases like DNS rebinding, `0.0.0.0`, IPv6 loopback forms, and redirects.
- If arbitrary user-supplied URLs must be fetched, resolve the hostname first, reject requests where the resolved IP is in a private/loopback/link-local range (RFC 1918, 127.0.0.0/8, 169.254.0.0/16, ::1, fc00::/7) or is the known cloud metadata address (169.254.169.254), and disable automatic redirect-following (or re-validate the target on every redirect hop).
- Restrict the URL scheme to `http`/`https` only — reject `file://`, `gopher://`, `dict://`, etc.
- Set a short timeout and don't return the raw response body to the client if this is fetching on the client's behalf — that turns SSRF into a blind port scanner otherwise.
