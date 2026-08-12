# Insufficiently Protected Credentials (CWE-522)

**Root cause:** a password, token, or other credential is stored or logged in plaintext instead of hashed (for passwords) or encrypted-at-rest (for tokens/API keys that must be recoverable).

**Fix pattern:** distinguish what the credential needs — passwords should never be recoverable, so hash them; other credentials (API tokens the app must present to a third party) need encryption at rest, since they must be decryptable.

- Passwords: hash with bcrypt/argon2/scrypt before storage (see [[weak-crypto]] if the current code uses a fast general-purpose hash like SHA-256/MD5 instead) — never store or log the plaintext password anywhere, including debug logs.
- Session/API tokens the app must reuse: encrypt at rest (e.g. via the platform's secrets manager or an application-level encryption key kept outside the database), don't store them in plaintext columns.
- Logging: check whether the credential is also being written to logs (request/response logging, error logs, analytics) — redact it there too; fixing storage alone doesn't fix a logging leak.
- If credentials are currently sent over plaintext HTTP or an unencrypted channel, that's a separate but related gap worth flagging even if it's outside the immediate diff.
