# SQL Injection remediation notes (offline digest)

> Project-authored summary used ONLY when the live OWASP cheat sheets cannot be fetched
> (offline mode, CI without network). It paraphrases the guidance; the ingestion
> pipeline pulls the authoritative OWASP Cheat Sheet Series text when online.
> Sources: OWASP SQL Injection Prevention Cheat Sheet, OWASP Query Parameterization
> Cheat Sheet (CC BY-SA 4.0).

## Why it happens

Injection occurs when an application builds a SQL statement by combining trusted query
text with untrusted input. The database cannot tell which characters were meant as data
and which as syntax, so crafted input can change the statement's structure: adding
conditions, terminating it, or appending new statements.

## Primary defense: parameterized queries

Write the SQL text with placeholders and pass every untrusted value separately through
the driver's binding API (prepared statements). The database parses the query structure
before any value is attached, so values can never become syntax. This is the preferred
fix in every mainstream language and is usually the simplest change to review.

- Python DB-API drivers: placeholders such as `%s` or `%(name)s` plus a params argument.
- Node.js: driver placeholders (`$1`, `?`) with a values array.
- Java: `PreparedStatement` with typed `setX` calls, or named parameters in Spring.

## Stored procedures

Stored procedures are only safe when they themselves use parameters. A procedure that
concatenates its arguments into dynamic SQL internally is just as injectable.

## Allowlist validation for what cannot be bound

Identifiers such as table names, column names and sort direction cannot be supplied as
bind parameters. Map user-facing choices onto a fixed set of known-good identifiers in
code (an allowlist) and reject everything else. Do not attempt to sanitise free-form
identifiers.

## Escaping is a last resort

Escaping user input for a specific database is fragile and database-specific. It should
not be used as the primary defense and is not a substitute for parameterization.

## ORMs and query builders

ORMs parameterize values when you use their query APIs, but their raw-SQL escape hatches
(`raw`, `text`, `query`, native queries) are exactly as dangerous as plain string
building unless they are used with their bind-parameter options.

## Defense in depth

- Run the application with a least-privilege database account (no DDL, no access to
  unrelated schemas).
- Validate type and range of inputs (e.g. integers for ids) before they reach data access.
- Avoid exposing database error details to clients.
