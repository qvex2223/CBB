#!/usr/bin/env python3
"""identity.py: the tool provisions its own test accounts, never asks the operator,
and every policy refusal is a structured block instead of a question."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import identity as ID  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.proj = self.root / "Targets" / "testeng"
        self.proj.mkdir(parents=True)
        (self.root / "Targets" / "testeng" / "scope.md").write_text(
            "# Scope\n\n## In scope\n- `*.acme.com`\n")
        (self.root / "hunt-memory").mkdir()
        self._env = dict(os.environ)
        os.environ["CBH_MEMORY_DIR"] = str(self.root / "hunt-memory")
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def _mailtm_ok(self, url, **kw):
        if url.endswith("/domains"):
            return {"hydra:member": [{"domain": "mail.test"}]}
        if url.endswith("/accounts"):
            return {"id": "acc1"}
        if url.endswith("/token"):
            return {"token": "jwt-fake"}
        if "/messages" in url:
            return {"hydra:member": []}
        raise AssertionError(f"unexpected url {url}")


class Provisioning(Base):
    def test_happy_path_mints_email_and_stores_it_0600(self):
        with mock.patch.object(ID, "_http_json", side_effect=self._mailtm_ok):
            ident = ID.provision("https://app.acme.com/signup", start=self.proj)
        self.assertEqual(ident["status"], "ready")
        self.assertTrue(ident["email"].endswith("@mail.test"))
        self.assertIsNone(ident["phone"], "no sms provider configured must be email-only")
        on_disk = self.proj / ID.IDENTITY_FILE
        data = json.loads(on_disk.read_text())
        self.assertEqual(data["email"], ident["email"])
        self.assertEqual(oct(on_disk.stat().st_mode & 0o777), "0o600")

    def test_out_of_scope_host_refuses_without_any_network(self):
        with mock.patch.object(ID, "_http_json",
                               side_effect=AssertionError("network must not be touched")):
            ident = ID.provision("https://evil.example.com/signup", start=self.proj)
        self.assertEqual(ident["status"], "blocked")
        self.assertIn("scope", ident["reason"])
        self.assertFalse((self.proj / ID.IDENTITY_FILE).exists())

    def test_profile_can_disable_self_registration(self):
        (self.proj / "profile.json").write_text(json.dumps({
            "project": "testeng", "self_registration": False}))
        ident = ID.provision("https://app.acme.com/signup", start=self.proj)
        self.assertEqual(ident["status"], "blocked")
        self.assertIn("disabled", ident["reason"])

    def test_provider_outage_is_a_block_not_a_question(self):
        with mock.patch.object(ID, "_http_json", side_effect=OSError("timeout")):
            ident = ID.provision("https://app.acme.com/signup", start=self.proj)
        self.assertEqual(ident["status"], "blocked")
        self.assertIn("provider error", ident["reason"])

    def test_no_engagement_is_a_block_not_a_question(self):
        ident = ID.provision("https://app.acme.com/", start=self.root / "elsewhere")
        self.assertEqual(ident["status"], "blocked")

    def test_audit_never_sees_the_password(self):
        with mock.patch.object(ID, "_http_json", side_effect=self._mailtm_ok):
            ident = ID.provision("https://app.acme.com/signup", start=self.proj)
        audit = self.root / "hunt-memory" / "audit.jsonl"
        if audit.exists():
            blob = audit.read_text()
        else:
            blob = ""
        self.assertNotIn(ident["password"], blob)
        self.assertNotIn(ident["token"], blob)


class Phone(Base):
    def test_sms_provider_roundtrip(self):
        cfg = {"kind": "sms-activate", "api_key_env": "CBH_FAKE_KEY",
               "service": "ot", "country": 0}
        os.environ["CBH_FAKE_KEY"] = "k"
        calls = []

        def fake(initial_cfg, **params):
            calls.append(params)
            if params["action"] == "getNumber":
                return "ACCESS_NUMBER:777:77001234567"
            if params["action"] == "getStatus":
                return "STATUS_OK:123456"
            raise AssertionError(params)

        with mock.patch.object(ID, "_sms_call", side_effect=fake):
            number, act, reason = ID.provision_phone({"sms_provider": cfg})
            self.assertEqual((number, act), ("77001234567", "777"))
            self.assertEqual(ID.phone_code(cfg, act), "123456")

    def test_no_provider_configured_is_email_only(self):
        os.environ.pop("CBH_FAKE_KEY", None)
        number, act, reason = ID.provision_phone({"sms_provider": {
            "kind": "sms-activate", "api_key_env": "CBH_FAKE_KEY"}})
        self.assertIsNone(number)
        self.assertIn("no sms_provider", reason)

    def test_provider_refusal_mentions_the_reason(self):
        cfg = {"kind": "sms-activate", "api_key_env": "CBH_FAKE_KEY"}
        os.environ["CBH_FAKE_KEY"] = "k"
        with mock.patch.object(ID, "_sms_call", return_value="NO_NUMBERS"):
            number, act, reason = ID.provision_phone({"sms_provider": cfg})
        self.assertIsNone(number)
        self.assertIn("NO_NUMBERS", reason)


class Redaction(unittest.TestCase):
    def test_redacted_copy_keeps_address_hides_secrets(self):
        ident = {"address": "a@b.c", "password": "pw", "token": "tk", "email": "a@b.c"}
        red = ID.redacted_copy(ident)
        self.assertEqual(red["password"], "<redacted>")
        self.assertEqual(red["token"], "<redacted>")
        self.assertEqual(red["email"], "a@b.c")


if __name__ == "__main__":
    unittest.main()
