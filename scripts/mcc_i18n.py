"""DE/EN UI strings for MCC (BUG-018: MCC_LOCALE / ui_locale in mcc_ui.json)."""

from __future__ import annotations

import os

_UI_LOCALE: str | None = None

_STR: dict[str, dict[str, str]] = {
    "de": {
        "app_title": "MCC",
        "unlock_title": "MCC entsperren",
        "about_menu": "Über MCC",
        "about_title": "MCC",
        "about_body": (
            "MCC — Modell-Kontext-Steuerung\n"
            "https://modelcontextcontrol.io/\n"
            "https://github.com/EvolutionKi/modelcontextcontrol\n\n"
            "Governance-Schicht für MCP: Richtlinien, Audit, Blocklisten.\n"
            "Diese Oberfläche: Monitoring, Policy, OAuth, Server/Tunnel, Export."
        ),
        "stack_start": "Stack starten",
        "stack_stop": "Stack stoppen",
        "build_ok": "Build erfolgreich: dist/MCC.exe",
        "build_fail": "Build fehlgeschlagen. Details im Betriebslog.",
        "tunnel_default_hint": "Optional: öffentliche Basis-URL (leer = nur lokal).",
        "first_run_title": "Willkommen bei MCC",
        "first_run_intro": (
            "MCC (Model Context Control) schränkt MCP-Dateizugriff per Policy ein.\n\n"
            "Standard: read_only, Sie legen Roots und Schreibpfade bewusst fest.\n"
            "Terminal- und Kontext-Stunden-Tools sind in MCC nicht enthalten."
        ),
        "first_run_checkbox": "Ich habe verstanden, dass ohne freigegebene Roots kein Zugriff möglich ist.",
        "first_run_continue": "Weiter",
        "first_run_locale_label": "Sprache / Language:",
        "disconnect_already": (
            "In dieser Sitzung wurde bereits getrennt und exportiert.\n\n"
            "Zuerst „Stack starten“, danach steht „Trennen + Export“ wieder zur Verfügung."
        ),
        "disconnect_ok": "Verbindung getrennt.\n\nExport:\n{path}",
        "activity_stopped": "GESTOPPT",
        "activity_suspicious": "VERDÄCHTIG",
        "activity_upload": "UPLOAD AKTIV",
        "activity_active": "AKTIV",
        "status_idle_healthy": "BEREIT",
        "toast_suspicious": "Neue verdächtige Zugriffe im Log.",
        "copy_ok": "In Zwischenablage kopiert.",
        "copy_callback_url": "OAuth-Callback-URL in die Zwischenablage kopiert.",
        "health_toast_title": "MCC Health",
        "menu_file": "Datei",
        "menu_view": "Ansicht",
        "menu_help": "Hilfe",
        "m_export_now": "Jetzt exportieren",
        "m_disconnect": "Trennen + Export",
        "m_save_policy": "Policy speichern",
        "m_snapshot_export": "Einstellungs-Snapshot exportieren …",
        "m_snapshot_import": "Einstellungs-Snapshot importieren …",
        "m_change_master": "Master-Passwort ändern …",
        "m_keystore_export": "Keystore als Klartext exportieren …",
        "m_quit": "Beenden",
        "m_dark": "Dark Mode",
        "m_access_log": "Access-Log (heute) öffnen",
        "m_help_show": "Hilfe anzeigen",
        "m_help_save": "Kurzanleitung speichern",
        "m_about": "Über",
        "m_lang": "Sprache",
        "m_lang_de": "Deutsch",
        "m_lang_en": "English",
        "sec_monitoring": "Monitoring",
        "sec_policy": "Policy",
        "sec_auth": "Auth / Connector",
        "sec_blocklist": "Blocklist",
        "sec_ops": "Betrieb",
        "sec_advanced": "Erweitert",
        "sec_help": "Hilfe",
        "status_section_fmt": "Status: Bereich {section}",
        "status_ready": "Status: bereit",
        "url_tunnel_prefix": "Tunnel-URL:",
        "acc_s": "Strg+S",
        "acc_e": "Strg+E",
        "acc_q": "Strg+Q",
    },
    "en": {
        "app_title": "MCC",
        "unlock_title": "Unlock MCC",
        "about_menu": "About MCC",
        "about_title": "MCC",
        "about_body": (
            "MCC — Model Context Control\n"
            "https://modelcontextcontrol.io/\n"
            "https://github.com/EvolutionKi/modelcontextcontrol\n\n"
            "Open governance layer for MCP: policy, audit, blocklists.\n"
            "This UI: monitoring, policy, OAuth, server/tunnel, export."
        ),
        "stack_start": "Start stack",
        "stack_stop": "Stop stack",
        "build_ok": "Build successful: dist/MCC.exe",
        "build_fail": "Build failed. See operations log.",
        "tunnel_default_hint": "Optional: public base URL (empty = local only).",
        "first_run_title": "Welcome to MCC",
        "first_run_intro": (
            "MCC (Model Context Control) enforces MCP file access via policy.\n\n"
            "Default: read_only; you explicitly configure roots and write paths.\n"
            "Terminal and hourly context tools are not part of MCC."
        ),
        "first_run_checkbox": "I understand that without configured roots there is no access.",
        "first_run_continue": "Continue",
        "first_run_locale_label": "Language:",
        "disconnect_already": (
            "This session already disconnected and exported.\n\n"
            "Start the stack again to use “Disconnect + export”."
        ),
        "disconnect_ok": "Disconnected.\n\nExport:\n{path}",
        "activity_stopped": "STOPPED",
        "activity_suspicious": "SUSPICIOUS",
        "activity_upload": "UPLOAD ACTIVE",
        "activity_active": "ACTIVE",
        "status_idle_healthy": "IDLE OK",
        "toast_suspicious": "New suspicious access events in the log.",
        "copy_ok": "Copied to clipboard.",
        "copy_callback_url": "OAuth callback URL copied to clipboard.",
        "health_toast_title": "MCC Health",
        "menu_file": "File",
        "menu_view": "View",
        "menu_help": "Help",
        "m_export_now": "Export now",
        "m_disconnect": "Disconnect + export",
        "m_save_policy": "Save policy",
        "m_snapshot_export": "Export settings snapshot…",
        "m_snapshot_import": "Import settings snapshot…",
        "m_change_master": "Change master password…",
        "m_keystore_export": "Export keystore as plaintext…",
        "m_quit": "Quit",
        "m_dark": "Dark mode",
        "m_access_log": "Open today’s access log",
        "m_help_show": "Show help",
        "m_help_save": "Save quick help",
        "m_about": "About",
        "m_lang": "Language",
        "m_lang_de": "German",
        "m_lang_en": "English",
        "sec_monitoring": "Monitoring",
        "sec_policy": "Policy",
        "sec_auth": "Auth / connector",
        "sec_blocklist": "Blocklist",
        "sec_ops": "Operations",
        "sec_advanced": "Advanced",
        "sec_help": "Help",
        "status_section_fmt": "Status: {section}",
        "status_ready": "Status: ready",
        "url_tunnel_prefix": "Tunnel URL:",
        "acc_s": "Ctrl+S",
        "acc_e": "Ctrl+E",
        "acc_q": "Ctrl+Q",
    },
}


def set_ui_locale(code: str | None) -> None:
    """Persistente UI-Sprache (wird von mcc_ui.json geladen)."""
    global _UI_LOCALE
    if code is None or str(code).strip() == "":
        _UI_LOCALE = None
        return
    c = str(code).strip().lower()
    _UI_LOCALE = c if c in _STR else None


def mcc_locale() -> str:
    if _UI_LOCALE in _STR:
        return _UI_LOCALE
    raw = (os.environ.get("MCC_LOCALE") or os.environ.get("LANG") or "de").replace("-", "_").lower()
    primary = raw.split("_")[0]
    return primary if primary in _STR else "de"


def t(key: str) -> str:
    lang = mcc_locale()
    return _STR.get(lang, _STR["de"]).get(key, _STR["de"].get(key, key))
