# Hardcoded Credentials / Cryptographic Keys (CWE-798, CWE-321)

**Root cause:** a secret (API key, password, signing key, private key) is committed as a literal in source rather than supplied at runtime.

**Fix pattern:** remove the literal from the source and load it from environment variables or a secrets manager instead.

- Replace the literal with `process.env.SECRET_NAME` (Node), `os.environ["SECRET_NAME"]` (Python), etc., and document the required env var (e.g. in `.env.example`, never `.env` itself).
- For production systems, prefer a secrets manager (Vault, AWS/GCP/Azure secret stores) over plain env vars where the codebase already uses one.
- The exposed secret must be treated as compromised even after the code fix — call out in the explanation that it needs to be rotated/revoked at the provider, since removing it from source doesn't undo prior exposure (it's likely still in git history).
- Add the config file that will hold the real value (`.env`, `secrets.yaml`, etc.) to `.gitignore` if it isn't already.
