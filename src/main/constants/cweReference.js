// Static CWE/OWASP grounding for the scanner prompt -- the RAG-lite
// alternative to standing up an embedding model + vector DB. Small enough
// to always include in full rather than retrieve a subset, which also
// keeps behavior deterministic across scans instead of depending on
// whatever a similarity search happened to surface.
const CWE_REFERENCE = `Common vulnerability classes to check for (CWE / OWASP mapping), grounded to the code you're actually shown -- do not report a category just because it's on this list:
- CWE-89 SQL Injection -- unsanitized input concatenated/interpolated into a query string.
- CWE-78 OS Command Injection -- unsanitized input passed to a shell (exec/system/subprocess with shell=True).
- CWE-79 Cross-Site Scripting (XSS) -- unsanitized input written into HTML/DOM (innerHTML, document.write, template rendering without escaping).
- CWE-94 Code Injection -- unsanitized input passed to eval/exec/Function constructor/deserialization of executable code.
- CWE-798 / CWE-321 Hardcoded Credentials or Cryptographic Keys -- secrets, API keys, or signing keys committed in source rather than loaded from config/secret storage.
- CWE-306 Missing Authentication for Critical Function -- an endpoint/action that lacks an auth check present on comparable endpoints elsewhere in the codebase.
- CWE-862 / CWE-863 Missing or Incorrect Authorization -- authenticated but not authorized (e.g. no ownership/role check before acting on a resource ID from the request).
- CWE-352 Cross-Site Request Forgery -- state-changing endpoint with no CSRF protection.
- CWE-502 Insecure Deserialization -- deserializing untrusted data (pickle, yaml.load, unsafe JSON->object mapping) that can lead to code execution.
- CWE-611 XML External Entity (XXE) -- XML parsing with external entity resolution enabled on untrusted input.
- CWE-918 Server-Side Request Forgery (SSRF) -- server makes an outbound request to a URL derived from user input without validation.
- CWE-295 Improper Certificate Validation -- TLS verification disabled or weakened (rejectUnauthorized: false, verify=False).
- CWE-326 / CWE-327 Weak or Broken Cryptography -- MD5/SHA1 for security purposes, ECB mode, predictable IVs/nonces, home-rolled crypto.
- CWE-732 Incorrect Permission Assignment -- overly permissive file/resource permissions or default-allow access control.
- CWE-639 Insecure Direct Object Reference (IDOR) -- a request parameter directly selects a resource with no ownership check.
- CWE-522 Insufficiently Protected Credentials -- passwords/tokens stored or logged in plaintext.`;

module.exports = { CWE_REFERENCE };
