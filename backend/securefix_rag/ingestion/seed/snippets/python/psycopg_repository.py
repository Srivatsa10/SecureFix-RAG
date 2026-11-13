"""Approved pattern: psycopg (v3) repository functions with bound parameters.

House rules:
- SQL text is a constant string; values are ALWAYS passed as the second argument.
- Positional `%s` for short queries, named `%(name)s` when there are 3+ parameters.
- Dynamic identifiers (table/column names) use `psycopg.sql.Identifier`, never f-strings.
- Repository functions take a connection, never build their own.
"""

from psycopg import Connection, sql
from psycopg.rows import dict_row


def find_user_by_email(conn: Connection, email: str) -> dict | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, email, display_name FROM users WHERE email = %s",
            (email,),
        )
        return cur.fetchone()


def search_orders(conn: Connection, customer_id: int, status: str, limit: int) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, total_cents, status, created_at
            FROM orders
            WHERE customer_id = %(customer_id)s
              AND status = %(status)s
            ORDER BY created_at DESC
            LIMIT %(limit)s
            """,
            {"customer_id": customer_id, "status": status, "limit": limit},
        )
        return cur.fetchall()


def count_rows(conn: Connection, table_name: str) -> int:
    # Identifiers cannot be bound as values; compose them with sql.Identifier, which quotes
    # them safely. The table name must still come from an allowlist (see validation.py).
    query = sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table_name))
    with conn.cursor() as cur:
        cur.execute(query)
        (count,) = cur.fetchone()
        return count


def insert_audit_events(conn: Connection, events: list[tuple[int, str]]) -> None:
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO audit_events (user_id, action) VALUES (%s, %s)",
            events,
        )
