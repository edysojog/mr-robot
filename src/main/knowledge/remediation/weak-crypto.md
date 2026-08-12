# Weak or Broken Cryptography (CWE-326, CWE-327)

**Root cause:** a cryptographically broken or inappropriate primitive is used for a security purpose — MD5/SHA1 for password hashing or integrity, ECB mode, a fixed/predictable IV or nonce, or a hand-rolled cipher/encoding presented as encryption.

**Fix pattern:** swap in the standard, purpose-appropriate primitive; don't try to "strengthen" the broken one.

- Password hashing: use bcrypt/scrypt/argon2 (via the ecosystem's standard library — `bcrypt`, `argon2`, Python's `passlib`, Java's `BCryptPasswordEncoder`) — never MD5/SHA1/SHA256 alone, even salted, for passwords.
- Data integrity/checksums where security matters: SHA-256 or better, not MD5/SHA1.
- Symmetric encryption: AES-GCM (authenticated) rather than AES-ECB or AES-CBC without a MAC; generate a fresh random IV/nonce per encryption operation with a CSPRNG (`crypto.randomBytes`, `os.urandom`, `SecureRandom`) — never a fixed or counter-derived IV reused across calls in a way that repeats.
- Random values used for tokens/secrets: use the platform CSPRNG (`crypto.randomBytes`, `secrets` module, `SecureRandom`), never `Math.random()`/`random.random()`.
- If this is a case of encrypting for confidentiality, use an established authenticated scheme end-to-end rather than composing primitives by hand.
