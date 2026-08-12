# Improper Certificate Validation (CWE-295)

**Root cause:** TLS certificate verification has been explicitly disabled or weakened, usually to work around a local/self-signed cert during development, and the change shipped.

**Fix pattern:** remove the override and fix the actual trust problem instead of disabling verification.

- Node: remove `rejectUnauthorized: false` (on `https.request`, `tls.connect`, or `NODE_TLS_REJECT_UNAUTHORIZED=0`). If the target uses an internal/self-signed CA, pass that CA's cert via the `ca` option instead of disabling verification globally.
- Python (`requests`/`urllib3`): remove `verify=False`; if a private CA is involved, pass `verify='/path/to/ca-bundle.pem'`.
- Java: remove custom `TrustManager`/`HostnameVerifier` implementations that accept everything; use the JVM's default trust store, or import the private CA into a proper truststore.
- If this genuinely needs to run against a self-signed cert in a dev/test environment only, scope the bypass to that environment explicitly (env-var-gated, never the default) rather than disabling it in code that also runs in production.
