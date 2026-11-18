import importlib.util
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location("setup_script", pathlib.Path(__file__).with_name("device-trust-setup.py"))
setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(setup)

# Shaped like the real `cert-issuer` policy in bootstrap.py: several unrelated paths every service depends on.
EXISTING = '''path "pki/issue/internal-services" {
  capabilities = ["create", "update"]
}
path "secret/data/password-pepper" {
  capabilities = ["read", "create", "update"]
}
path "secret/data/scim/*" {
  capabilities = ["read", "create", "update"]
}
'''


class WithSigningPermission(unittest.TestCase):
    def test_everything_already_in_the_policy_is_preserved_exactly(self):
        updated, changed = setup.with_signing_permission(EXISTING)
        self.assertTrue(changed)
        self.assertTrue(updated.startswith(EXISTING.rstrip("\n")), "the original text must come first, untouched")
        for path in ("pki/issue/internal-services", "secret/data/password-pepper", "secret/data/scim/*"):
            self.assertIn(f'path "{path}"', updated)

    def test_it_adds_exactly_one_narrow_permission(self):
        updated, _ = setup.with_signing_permission(EXISTING)
        self.assertEqual(updated.count('path "transit/sign/device-policy"'), 1)
        added = updated[len(EXISTING.rstrip("\n")):]
        self.assertIn('capabilities = ["update"]', added)
        self.assertNotIn("read", added)
        self.assertNotIn("transit/*", updated)  # never a wildcard over other keys
        self.assertEqual(added.count("path "), 1)

    def test_running_it_again_changes_nothing(self):
        once, _ = setup.with_signing_permission(EXISTING)
        twice, changed_again = setup.with_signing_permission(once)
        self.assertFalse(changed_again)
        self.assertEqual(once, twice)

    def test_it_works_on_an_empty_policy(self):
        updated, changed = setup.with_signing_permission("")
        self.assertTrue(changed)
        self.assertEqual(updated.count('path "transit/sign/device-policy"'), 1)


if __name__ == "__main__":
    unittest.main()
