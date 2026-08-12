# Incorrect Permission Assignment (CWE-732)

**Root cause:** a file, directory, or resource is created or left with broader access than it needs — world-writable/readable file permissions, an open default-allow ACL, or an overly permissive cloud resource policy.

**Fix pattern:** apply least-privilege permissions explicitly at creation time, scoped to only what actually needs access.

- File permissions (Unix): use the tightest mode the use case allows — `0600`/`0640` for files containing secrets or user data, `0644` at most for genuinely public files; avoid `0777`/`0666` entirely. In Node, pass `{ mode: 0o600 }` to `fs.writeFile`/`fs.open`; in Python, `os.open(path, flags, 0o600)` or `os.chmod` right after creation.
- Directories: avoid world-writable directories (`0777`); use `0750`/`0755` and restrict write access to the owning process/user.
- Cloud storage (S3 buckets, GCS, Azure blobs): remove public-read/public-write policies unless the resource is genuinely meant to be public; scope IAM policies to the specific principals and actions needed rather than `*`.
- If the code sets permissions to work around a "permission denied" error, fix the actual ownership/group membership rather than widening the mode.
