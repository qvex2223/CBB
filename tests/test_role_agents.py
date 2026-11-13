"""The crew roles are one source rendered per client.

Session a0053cc0 spawned 138 subagents, all `general-purpose`, briefed by hand: `victim` in
15 briefs of 138, `forbidden` in 15. These tests hold the two blocks that were missing in
place, and hold them identical across every client the generator renders for — one of
them since 2026-11-13 (`.claude/agents/`), the renderer itself still per-client.
"""
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "agents"))
import gen_role_agents as g  # noqa: E402

ROLES = ("deep-hunter", "scout", "refuter")


class RoleAgents(unittest.TestCase):
    def test_every_client_gets_every_role(self):
        for role in ROLES:
            for d in g.OUT.values():
                self.assertTrue((d / f"{role}.md").exists(), f"{d}/{role}.md")

    def test_generated_files_are_current(self):
        r = subprocess.run([sys.executable, str(REPO / "agents/gen_role_agents.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(0, r.returncode,
                         r.stdout + r.stderr + "\nre-run python3 agents/gen_role_agents.py")

    def test_check_catches_a_stale_output(self):
        p = REPO / ".claude" / "agents" / "scout.md"
        original = p.read_text(encoding="utf-8")
        try:
            p.write_text(original + "\nedited by hand\n", encoding="utf-8")
            r = subprocess.run([sys.executable, str(REPO / "agents/gen_role_agents.py"), "--check"],
                               capture_output=True, text=True)
            self.assertEqual(1, r.returncode)
            self.assertIn("STALE", r.stdout)
        finally:
            p.write_text(original, encoding="utf-8")

    def test_every_role_carries_the_forbidden_list_and_the_gate(self):
        for role in ROLES:
            for client in g.OUT:
                text = g.render(g.SRC / f"{role}.md", client)
                self.assertIn("Forbidden on every engagement", text, role)
                self.assertIn("bbcurl", text, role)
                self.assertIn("blocked-tests/", text, role)
                self.assertIn("own accounts and data only", text, role)

    def test_the_sending_roles_must_name_a_victim(self):
        for role in ("deep-hunter", "refuter"):
            text = g.render(g.SRC / f"{role}.md", "claude")
            self.assertIn("Impact needs a named victim", text, role)
            self.assertIn("primitives/", text, role)

    def test_the_shared_blocks_do_not_differ_between_clients(self):
        """`{{SAFETY}}` and `{{VICTIM}}` are shared text: a rule that reaches one
        client only is the drift these blocks exist to prevent."""
        clients = list(g.OUT)
        for role in ROLES:
            rendered = {c: g.render(g.SRC / f"{role}.md", c) for c in clients}
            for block in (g.SAFETY, g.VICTIM):
                present = [c for c in clients if block in rendered[c]]
                self.assertIn(len(present), (0, len(clients)),
                              f"{role}: block drifted between clients ({present})")

    def test_the_per_client_difference_is_only_the_skill_call_and_the_note(self):
        text = g.render(g.SRC / "deep-hunter.md", "claude")
        self.assertIn("Skill(hunt-<class>)", text)
        self.assertIn("in-process `Agent` subagent", text)
        # the two placeholders are the whole per-client surface: everything else is
        # shared text, which the drift test above holds
        self.assertEqual(set(g.OUT), set(g.SKILL) & set(g.NOTE))

    def test_no_placeholder_survives_into_an_output(self):
        for role in ROLES:
            for client in g.OUT:
                text = g.render(g.SRC / f"{role}.md", client)
                for ph in ("{{SAFETY}}", "{{VICTIM}}", "{{SKILL}}"):
                    self.assertNotIn(ph, text, f"{role}/{client}")

    def test_the_frontmatter_name_matches_the_filename(self):
        for role in ROLES:
            head = (g.SRC / f"{role}.md").read_text(encoding="utf-8").split("\n---\n")[0]
            self.assertIn(f"name: {role}", head)

    def test_the_agent_gate_knows_each_role(self):
        sys.path.insert(0, str(REPO / "scripts"))
        import importlib.util
        spec = importlib.util.spec_from_file_location("agent_gate", REPO / "scripts/agent-gate.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        known = {"hunter", "scout", "review", "general"}
        for role in ROLES:
            self.assertIn(role, m.ROLE_BY_TYPE, f"{role} missing from ROLE_BY_TYPE")
            # the value is the role KEY the audit and the briefs are written against; a
            # value outside the set silently degrades the worker to "general"
            self.assertIn(m.ROLE_BY_TYPE[role], known,
                          f"{role} maps to a role key nothing knows")


if __name__ == "__main__":
    unittest.main()
