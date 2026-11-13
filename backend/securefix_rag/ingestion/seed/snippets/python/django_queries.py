"""Approved pattern: Django ORM queries.

House rules:
- Use QuerySet filters (`filter`, `exclude`, `Q`) - values are parameterized by the ORM.
- `Model.objects.raw()` and `cursor.execute()` take a `params` list; never format SQL.
- `extra()` and `RawSQL` with interpolated input are banned in code review.
- `order_by()` arguments come from an allowlist, never directly from `request.GET`.
"""

from django.db import connection
from django.db.models import Q
from shop.models import Customer, Order

ORDER_SORT_FIELDS = {"newest": "-created_at", "oldest": "created_at", "total": "-total_cents"}


def search_customers(query: str) -> list[Customer]:
    return list(Customer.objects.filter(Q(name__icontains=query) | Q(email__icontains=query))[:50])


def orders_for_customer(customer_id: int, sort: str = "newest") -> list[Order]:
    ordering = ORDER_SORT_FIELDS.get(sort, ORDER_SORT_FIELDS["newest"])
    return list(Order.objects.filter(customer_id=customer_id).order_by(ordering))


def top_customers_raw(region: str, min_orders: int) -> list[Customer]:
    return list(
        Customer.objects.raw(
            "SELECT c.* FROM shop_customer c "
            "JOIN shop_order o ON o.customer_id = c.id "
            "WHERE c.region = %s GROUP BY c.id HAVING COUNT(o.id) >= %s",
            [region, min_orders],
        )
    )


def refund_total(order_id: int) -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT COALESCE(SUM(amount_cents), 0) FROM shop_refund WHERE order_id = %s",
            [order_id],
        )
        (total,) = cursor.fetchone()
        return total
