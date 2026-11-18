"""A synthetic object-authorization lab, not an authentication service."""
from dataclasses import dataclass


class AccessDenied(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = False


@dataclass(frozen=True)
class Order:
    order_id: str
    tenant: str
    owner: str
    status: str


def insecure_read(orders: dict[str, Order], order_id: str) -> Order:
    """Intentionally vulnerable baseline: knowing an ID grants access."""
    return orders[order_id]


def read_order(principal: Principal, orders: dict[str, Order], order_id: str) -> Order:
    """Require trusted identity, tenant binding, and object permission."""
    order = orders.get(order_id)
    if (
        not principal.authenticated
        or not principal.subject
        or not principal.tenant
        or order is None
        or not order.tenant
        or order.tenant != principal.tenant
    ):
        raise AccessDenied("Order access denied")
    owns_order = "customer" in principal.roles and order.owner == principal.subject
    is_support = "support" in principal.roles
    if not (owns_order or is_support):
        raise AccessDenied("Order access denied")
    return order
