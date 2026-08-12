# SQL Injection (CWE-89)

**Root cause:** untrusted input reaches the database as part of the query text instead of as data.

**Fix pattern:** use parameterized queries / prepared statements everywhere the query includes a variable — never build SQL with string concatenation, template literals, or `.format()`/f-strings, even for values that "look" numeric or safe.

- Node (pg/mysql2): `db.query('SELECT * FROM users WHERE id = $1', [id])`, not `` `SELECT * FROM users WHERE id = ${id}` ``.
- Python (psycopg2/sqlite3): `cur.execute("SELECT * FROM users WHERE id = %s", (id,))`, not `f"SELECT ... {id}"`.
- Java (JDBC): `PreparedStatement` with `?` placeholders, not `Statement` + string concat.
- ORMs (Sequelize, SQLAlchemy, ActiveRecord, Prisma): use the query builder's parameter binding, not `raw()`/`literal()` with interpolated strings.
- If the input selects a column/table name (which can't be parameterized), validate it against an allowlist of known-safe identifiers — never pass it through unchecked.

**Don't** just escape quotes or strip characters — that's an incomplete blocklist, not a fix.
