"""Smoke tests for MCC server surface (no live MCP port)."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


class TestToolCatalog(unittest.TestCase):
    def test_exec_tools_removed(self) -> None:
        import mcp_server as m

        names = [x["name"] for x in m._mcp_tools_catalog()]
        self.assertNotIn("run_terminal_command", names)
        self.assertNotIn("run_kontext_cowork_hourly", names)
        self.assertIn("read_file", names)
        self.assertIn("search_files", names)

    def test_blocked_file_env_suffix(self) -> None:
        import mcp_server as m

        pol = m.DEFAULT_POLICY
        p = Path("C:/tmp/example.env")
        self.assertTrue(m._is_blocked_file(p, pol))

    def test_blocked_file_env_glob_and_multidot_name(self) -> None:
        import mcp_server as m

        pol = m._deep_merge(m.DEFAULT_POLICY, {"blocked": {"suffixes": [".env.*"]}})
        self.assertTrue(m._is_blocked_file(Path("C:/tmp/.env.staging"), pol))
        self.assertTrue(m._is_blocked_file(Path("C:/tmp/.env.backup"), pol))
        pol2 = m.DEFAULT_POLICY
        self.assertTrue(m._is_blocked_file(Path("C:/tmp/.env.staging"), pol2))

    def test_python_automation_removed_from_server_module(self) -> None:
        import mcp_server as m

        self.assertFalse(hasattr(m, "_python_automation_snapshot"))

    def test_policy_integrity_defaults_when_block_missing(self) -> None:
        import mcp_server as m

        cfg = m._policy_integrity_config({"advanced": {}})
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["scope"], "selective")

    def test_inline_env_filename_blocked_via_name_contains(self) -> None:
        import mcp_server as m

        pol = m.DEFAULT_POLICY
        self.assertTrue(m._is_blocked_file(Path("C:/app/db.env.production"), pol))
        self.assertTrue(m._is_blocked_file(Path("C:/app/test.env.backup"), pol))

    def test_roots_empty_no_fallback(self) -> None:
        import mcp_server as m

        pol = m._deep_merge(m.DEFAULT_POLICY, {})
        roots = m._roots_from_policy_dict(pol)
        self.assertEqual(roots, [])

    def test_tool_registry_snapshot_custom_profiles(self) -> None:
        import mcp_server as m

        pol = m._deep_merge(
            m.DEFAULT_POLICY,
            {
                "tool_registry": {
                    "active_profile": "strict",
                    "disabled_tools": ["write_file"],
                    "custom_profiles": {"strict": {"disabled_tools": ["read_file", "write_file"]}},
                }
            },
        )
        snap = m._tool_registry_snapshot(pol)
        self.assertEqual(snap["active_profile"], "strict")
        self.assertIn("write_file", snap["disabled_tools"])
        self.assertIn("read_file", snap["custom_profiles"]["strict"]["disabled_tools"])


class TestReleaseGateAutomation(unittest.TestCase):
    """Teile des README-Release-Gates, die ohne frischen Windows-PC laufen."""

    def test_bundled_policy_has_no_evoki_in_write_allow(self) -> None:
        pol_path = ROOT / "config" / "mcp_policy.json"
        if not pol_path.is_file():
            self.skipTest("kein gebündeltes mcp_policy.json")
        data = json.loads(pol_path.read_text(encoding="utf-8"))
        perms = data.get("permissions") if isinstance(data, dict) else None
        self.assertIsInstance(perms, dict)
        allow = perms.get("write_allow_paths") if isinstance(perms, dict) else None
        self.assertIsInstance(allow, list)
        blob = json.dumps(allow, ensure_ascii=False).lower()
        self.assertNotIn("evoki", blob)

    def test_read_file_denies_blocked_file_before_open(self) -> None:
        """BUG-011: Suffix-Block (.pem) greift, Datei wird nicht gelesen (Pfad nicht unter %TEMP%/AppData)."""
        import mcp_server as m

        tmp = ROOT / ".pytest_mcc_tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        target = tmp / "blocked.pem"
        target.write_text("SECRET=1", encoding="utf-8")
        try:
            pol = m._deep_merge(m.DEFAULT_POLICY, {"roots": [str(ROOT.resolve())]})
            with mock.patch.object(m, "_get_policy", return_value=pol), mock.patch.object(
                m, "_run_request_pipeline", return_value=""
            ):
                with self.assertRaises(ValueError) as ar:
                    m.read_file(str(target.resolve()), max_bytes=500, ctx=None)
            self.assertIn("blocked", str(ar.exception).lower())
            self.assertEqual(target.read_text(encoding="utf-8"), "SECRET=1")
        finally:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass

    def test_no_standalone_evoki_branding_in_scripts_py(self) -> None:
        """README BRANDING: kein Produktname „EVOKI“ im Python-Quelltext (Dateiname evoki.py zählt nicht)."""
        token = re.compile(r"(?<![A-Za-z0-9])EVOKI(?![A-Za-z0-9])")
        for path in sorted(SCRIPTS.glob("*.py")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if token.search(text):
                self.fail(f"EVOKI-Branding in {path.relative_to(ROOT)}")


class TestMccI18n(unittest.TestCase):
    def test_set_ui_locale_overrides_env(self) -> None:
        import mcc_i18n as i18n

        i18n.set_ui_locale("en")
        self.assertEqual(i18n.mcc_locale(), "en")
        self.assertEqual(i18n.t("m_quit"), "Quit")
        i18n.set_ui_locale(None)
        self.assertIn(i18n.mcc_locale(), ("de", "en"))


if __name__ == "__main__":
    unittest.main()
