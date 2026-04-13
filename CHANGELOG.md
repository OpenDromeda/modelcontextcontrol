# Changelog — MCC

## 2026-04-13 — Guardian → MCC branding cleanup

- **Rename:** `scripts/mcp_guardian_app.py` → `scripts/mcc_app.py`
- **Rename class:** `GuardianControlCenter` → `MCCApp`
- **Rename env var:** `MCC_GUARDIAN_BASE` → `MCC_BASE`
- **Rename config:** `guardian_ui.json` → `mcc_ui.json`; `guardian_health.jsonl` → `mcc_health.jsonl`
- **Rename methods:** `_guardian_ui_settings_path` → `_ui_settings_path`, `_load_guardian_ui_settings` → `_load_ui_settings`, `_save_guardian_ui_settings` → `_save_ui_settings`, `_bootstrap_ui_locale_from_guardian_json` → `_bootstrap_ui_locale`
- **smoke_mcp_server.py:** German error strings migrated to English.
- **stop_mcc.py:** Removed EVOKI-internal port 20242 from port set.
- **requirements.txt:** Removed 6 EVOKI-only dependencies (`sentence-transformers`, `faiss-cpu`, `numpy`, `scipy`, `scikit-learn`, `google-generativeai`).
- **MCC.spec:** Entrypoint updated to `scripts/mcc_app.py`.
- **README.md / README_EN.md:** Dead links to `README_CURSOR_START_HERE.md` removed; `honeypot` removed from reserved policy fields list.

## 2026-04-12 — Post-source-review cleanup

- **Branding rename (filenames):** `scripts/mcp_readonly_evoki.py` → `scripts/mcp_server.py`; `scripts/start_evoki_guardian_stack.bat` → `scripts/start_mcc.bat`; `scripts/stop_evoki_guardian_stack.bat` → `scripts/stop_mcc.bat`; `scripts/stop_evoki_guardian_stack.py` → `scripts/stop_mcc.py`; `MCC_GUARDIAN_LITE.spec` → `MCC.spec`. All internal references updated accordingly.
- **Branding rename (display name):** FastMCP server display name `"MCC Lite"` → `"MCC"`.
- **Branding rename (build artifact):** PyInstaller `name="MCC_GUARDIAN_LITE"` → `name="MCC"`.
- **BUG-011b (security):** In `read_file`, blocklist check now runs before `is_file()` to prevent existence leaks via differential error messages.
- **BUG-018 (i18n):** All ~30 user-facing German strings in `mcp_server.py` migrated to English.
- **BUG-017 (cosmetic):** Removed remaining Terminal-MCP wording from `mcc_app.py`.
- **BUG-HELP:** `scripts/HELP.md` replaced with English quick-reference stub. `_help_content()` is now locale-aware.
- **Example policy hardening:** `permissions.mode` changed from `read_write` to `read_only`; extended-edition feature flags removed.
- **README updates:** Added *"Reservierte Policy-Felder"* / *"Reserved policy fields"* and *"Herkunft"* / *"Origin"* sections.
- **`.gitignore`:** Runtime artifacts added.

## 2026-04-09 — Public-release preparation

- **Website & Repo:** Official links [modelcontextcontrol.io](https://modelcontextcontrol.io/), [github.com/EvolutionKi/modelcontextcontrol](https://github.com/EvolutionKi/modelcontextcontrol).
- **Paths:** Config/logs default to `%USERPROFILE%\.mcc\`.
- **Policy default:** Empty `roots` and `read_only` for fresh installs.
- **Removed tools:** `run_terminal_command` and `run_kontext_cowork_hourly` not registered.
- **Security:** `read_file` checks blocklist before opening file handle.
- **Release-Gate:** Automated tests in `tests/test_mcc_lite.py`.
