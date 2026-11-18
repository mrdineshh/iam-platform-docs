"""Unit tests for the release tools (run: python -m unittest discover infra/agent-release -v)."""
import hashlib
import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publish = load(os.path.join(HERE, "publish.py"), "publish")
setup = load(os.path.join(HERE, "..", "openbao", "agent-release-setup.py"), "setup")


class StatementTests(unittest.TestCase):
    def test_statement_has_the_exact_shape_the_agent_and_backend_verify(self):
        self.assertEqual(publish.statement("WINDOWS", "x86_64", "0.3.1", "ab"), "iam-agent-release-v1\nWINDOWS\nx86_64\n0.3.1\nab")

    def test_payload_carries_the_real_hash_and_round_trips_the_bytes(self):
        data = b"MSI" * 100
        payload = publish.build_payload(data, "0.3.1", "vault:v1:abc", "PRODUCTION")
        self.assertEqual(payload["sha256"], hashlib.sha256(data).hexdigest())
        import base64
        self.assertEqual(base64.b64decode(payload["contentBase64"]), data)
        self.assertEqual((payload["platform"], payload["architecture"]), ("WINDOWS", "x86_64"))

    def test_version_format(self):
        for ok in ("0.3.1", "10.20.300"):
            self.assertTrue(publish.VERSION_RE.match(ok), ok)
        for bad in ("1.2", "1.2.3.4", "v1.2.3", "1.2.x", "", "1.2.3\n; rm"):
            self.assertFalse(publish.VERSION_RE.match(bad), bad)


class SetupGuardTests(unittest.TestCase):
    """The release key must never become reachable by the services' shared policy."""

    def test_detects_a_direct_grant(self):
        self.assertTrue(setup.policy_grants_key('path "transit/sign/agent-release" {\n  capabilities = ["update"]\n}'))

    def test_detects_wildcards_that_would_cover_it(self):
        for p in ("transit/*", "transit/sign/*", "transit/sign/agent-*", "transit/sign/agent-release/sha2-256"):
            self.assertTrue(setup.policy_grants_key(f'path "{p}" {{\n}}'), p)

    def test_the_policy_as_it_is_today_does_not_grant_it(self):
        today = '\n'.join(
            f'path "{p}" {{\n  capabilities = ["read"]\n}}'
            for p in ("pki/issue/internal-services", "secret/data/password-pepper", "secret/data/scim/*", "transit/sign/device-policy")
        )
        self.assertFalse(setup.policy_grants_key(today))

    def test_other_transit_keys_do_not_count(self):
        self.assertFalse(setup.policy_grants_key('path "transit/sign/device-policy" {\n}'))
        self.assertFalse(setup.policy_grants_key('path "secret/data/transit/*" {\n}'))


if __name__ == "__main__":
    unittest.main()
