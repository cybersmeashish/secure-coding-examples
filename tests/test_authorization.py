import unittest
from authorization import AccessDenied, Order, Principal, insecure_read, read_order


class ObjectAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.orders = {
            "a-1": Order("a-1", "tenant-a", "alice", "shipped"),
            "a-2": Order("a-2", "tenant-a", "adam", "pending"),
            "b-1": Order("b-1", "tenant-b", "bob", "shipped"),
        }
        self.alice = Principal("alice", "tenant-a", frozenset({"customer"}), True)

    def test_baseline_discloses_foreign_tenant_order(self):
        self.assertEqual(insecure_read(self.orders, "b-1").owner, "bob")

    def test_owner_can_read_own_order(self):
        self.assertEqual(read_order(self.alice, self.orders, "a-1").status, "shipped")

    def test_same_tenant_different_owner_is_denied(self):
        with self.assertRaises(AccessDenied):
            read_order(self.alice, self.orders, "a-2")

    def test_cross_tenant_identifier_is_denied(self):
        with self.assertRaises(AccessDenied):
            read_order(self.alice, self.orders, "b-1")

    def test_support_is_limited_to_its_tenant(self):
        support = Principal("agent-1", "tenant-a", frozenset({"support"}), True)
        self.assertEqual(read_order(support, self.orders, "a-2").owner, "adam")
        with self.assertRaises(AccessDenied):
            read_order(support, self.orders, "b-1")

    def test_unverified_client_role_does_not_authorize(self):
        unverified = Principal("mallory", "tenant-a", frozenset({"support"}))
        with self.assertRaises(AccessDenied):
            read_order(unverified, self.orders, "a-1")

    def test_missing_tenant_is_denied(self):
        principal = Principal("alice", "", frozenset({"customer"}), True)
        with self.assertRaises(AccessDenied):
            read_order(principal, self.orders, "a-1")

    def test_unknown_role_is_denied(self):
        principal = Principal("alice", "tenant-a", frozenset({"model-suggestion"}), True)
        with self.assertRaises(AccessDenied):
            read_order(principal, self.orders, "a-1")

    def test_missing_object_uses_same_denial(self):
        with self.assertRaisesRegex(AccessDenied, "^Order access denied$"):
            read_order(self.alice, self.orders, "missing")


if __name__ == "__main__":
    unittest.main()
