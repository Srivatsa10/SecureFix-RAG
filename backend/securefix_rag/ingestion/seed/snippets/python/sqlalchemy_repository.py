"""Approved pattern: SQLAlchemy 2.0 (ORM + Core) data access.

House rules:
- Prefer ORM `select()` expressions; column comparisons are bound automatically.
- When raw SQL is unavoidable, use `text()` with named `:param` bind parameters.
- Never pass user input to `text()` via f-strings or `%` formatting.
- Sorting uses an allowlist that maps request values onto real Column objects.
"""

from app.models import Invoice, User
from sqlalchemy import select, text
from sqlalchemy.orm import Session

SORTABLE_INVOICE_COLUMNS = {
    "created": Invoice.created_at,
    "amount": Invoice.amount_cents,
    "due": Invoice.due_date,
}


def get_user_by_username(session: Session, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    return session.scalars(stmt).first()


def list_invoices(session: Session, account_id: int, sort: str, descending: bool) -> list[Invoice]:
    column = SORTABLE_INVOICE_COLUMNS.get(sort)
    if column is None:
        raise ValueError(f"unsupported sort key: {sort!r}")
    order = column.desc() if descending else column.asc()
    stmt = select(Invoice).where(Invoice.account_id == account_id).order_by(order)
    return list(session.scalars(stmt))


def search_products_raw(session: Session, term: str, max_price_cents: int) -> list[dict]:
    stmt = text(
        "SELECT id, name, price_cents FROM products "
        "WHERE name ILIKE :pattern AND price_cents <= :max_price"
    )
    rows = session.execute(
        stmt, {"pattern": f"%{escape_like(term)}%", "max_price": max_price_cents}
    )
    return [dict(row._mapping) for row in rows]


def escape_like(value: str) -> str:
    """Escape LIKE wildcards so user input matches literally inside a bound pattern."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
