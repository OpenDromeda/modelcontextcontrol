import base64
import difflib
import fnmatch
import hashlib
import json
import os
import secrets
import shutil
import socket
import sys
import subprocess
import tempfile
import threading
import time
import tkinter as tk
import urllib.request
import urllib.error
from urllib.parse import urlencode
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, TextIO
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mcc_i18n import mcc_locale, set_ui_locale, t


class _SimpleTooltip:
    """Kleines Hover-Label (kein natives ttk-Tooltip)."""

    def __init__(self, parent: tk.Misc, widget: tk.Widget, text: str, delay_ms: int = 500) -> None:
        self._parent = parent
        self._widget = widget
        self._text = text
        self._delay_ms = delay_ms
        self._after_id: str | None = None
        self._win: tk.Toplevel | None = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)
        widget.bind("<ButtonPress>", self._hide)

    def _cancel_scheduled(self) -> None:
        if self._after_id is not None:
            try:
                self._widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _hide(self, _event: object | None = None) -> None:
        self._cancel_scheduled()
        if self._win is not None:
            try:
                self._win.destroy()
            except Exception:
                pass
            self._win = None

    def _schedule(self, _event: object | None = None) -> None:
        self._hide()
        self._after_id = self._widget.after(self._delay_ms, self._show)

    def _show(self) -> None:
        self._after_id = None
        if self._win is not None or not self._text:
            return
        x = self._widget.winfo_rootx() + 8
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 2
        self._win = tk.Toplevel(self._parent)
        self._win.wm_overrideredirect(True)
        try:
            self._win.wm_attributes("-topmost", True)
        except Exception:
            pass
        lbl = tk.Label(
            self._win,
            text=self._text,
            justify=tk.LEFT,
            background="#ffffe0",
            relief=tk.SOLID,
            borderwidth=1,
            font=("Segoe UI", 9),
            padx=6,
            pady=4,
        )
        lbl.pack()
        self._win.update_idletasks()
        self._win.geometry(f"+{x}+{y}")


def _frozen_app_base_dir() -> Path:
    """Projektroot für `config/` und `logs/` bei PyInstaller-EXE.

    Vorher war fest `exe.parent.parent` — das bricht, wenn die EXE direkt
    neben `config/` liegt oder nur auf dem Desktop kopiert wurde (dann wäre
    `parent.parent` oft der falsche Ort). Reihenfolge:

    1. Umgebungsvariable ``MCC_GUARDIAN_BASE`` oder ``MCC_BASE_DIR``
    2. ``exe_dir/config`` existiert → portable Installation (EXE + config im selben Ordner)
    3. ``exe_dir/../config`` existiert → klassisches Repo-Layout (z. B. ``dist/*.exe``)
    4. EXE unter ``…/scripts/dist/`` und ``…/config`` existiert (z. B. ``src/config``) →
       dieses Elternverzeichnis von ``scripts`` (nicht ``scripts/config``)
    5. Ordnername wie ``dist``/``build`` → neues ``config`` unter Repo-Root anlegen
    6. sonst: ``exe_dir`` (portable: config neben der EXE)
    """
    exe_path = Path(sys.executable).resolve()
    env_override = (
        os.environ.get("MCC_GUARDIAN_BASE")
        or os.environ.get("MCC_BASE_DIR")
        or ""
    ).strip()
    if env_override:
        return Path(env_override).expanduser().resolve()
    p = exe_path.parent
    gp = p.parent
    dist_like = p.name.lower() in {"dist", "build", "release", "win-unpacked", "debug"}
    if (p / "config").is_dir():
        return p
    if dist_like and gp.name.lower() == "scripts" and (gp.parent / "config").is_dir():
        return gp.parent
    if (gp / "config").is_dir():
        return gp
    if dist_like:
        return gp
    return p


if getattr(sys, 'frozen', False):
    BASE_DIR = _frozen_app_base_dir()
else:
    BASE_DIR = Path(__file__).resolve().parent.parent

CONFIG_DIR = BASE_DIR / "config"
LOG_DIR = BASE_DIR / "logs"
POLICY_FILE = CONFIG_DIR / "mcp_policy.json"
EXPORT_COUNTER_FILE = CONFIG_DIR / "export_counter.json"
KEYSTORE_PATH = CONFIG_DIR / "keystore.enc"
SALT_PATH = CONFIG_DIR / "keystore.salt"
BLOCKED_IPS_FILE = CONFIG_DIR / "blocked_ips.json"
HEALTH_LOG_FILE = LOG_DIR / "guardian_health.jsonl"

# Interne Tab-Schlüssel → i18n (BUG-018)
_SECTION_LABEL_KEYS: dict[str, str] = {
    "Monitoring": "sec_monitoring",
    "Policy": "sec_policy",
    "Auth/Connector": "sec_auth",
    "Blocklist": "sec_blocklist",
    "Betrieb": "sec_ops",
    "Erweitert": "sec_advanced",
    "Hilfe": "sec_help",
}


def _bootstrap_ui_locale_from_guardian_json() -> None:
    p = CONFIG_DIR / "guardian_ui.json"
    if not p.is_file():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return
        loc = str(data.get("ui_locale", "")).strip().lower()
        if loc in ("de", "en"):
            set_ui_locale(loc)
    except Exception:
        pass


# Keystore-JSON (neben Bearer-Keys codex/gpt): GitHub OAuth App
KEYSTORE_OAUTH_CLIENT_ID = "oauth_github_client_id"
KEYSTORE_OAUTH_CLIENT_SECRET = "oauth_github_client_secret"


def _today_access_log() -> Path:
    return LOG_DIR / f"mcp_access_{date.today().strftime('%Y%m%d')}.jsonl"


def _derive_fernet(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def unlock_keystore(password: str) -> dict[str, str] | None:
    try:
        salt = SALT_PATH.read_bytes()
        fernet = _derive_fernet(password, salt)
        raw = json.loads(fernet.decrypt(KEYSTORE_PATH.read_bytes()).decode("utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return None


def setup_keystore(password: str) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    SALT_PATH.write_bytes(salt)
    fernet = _derive_fernet(password, salt)
    KEYSTORE_PATH.write_bytes(fernet.encrypt(json.dumps({}).encode("utf-8")))


def save_keystore(password: str, store: dict[str, str]) -> None:
    salt = SALT_PATH.read_bytes()
    fernet = _derive_fernet(password, salt)
    KEYSTORE_PATH.write_bytes(fernet.encrypt(json.dumps(store).encode("utf-8")))
CF_LOG = BASE_DIR / "tools" / "cloudflared.log"
EXPORT_DIR = Path.home() / "Downloads"

DEFAULT_POLICY = {
    "roots": [],
    "permissions": {
        "mode": "read_only",
        "write_allow_paths": [],
        "write_deny_paths": [],
    },
    "blocked": {
        "dir_names": [
            ".git", ".svn", ".hg", ".idea", ".vscode", "node_modules", "__pycache__", ".venv", "venv",
            "$recycle.bin", "system volume information", "windows", "programdata"
        ],
        "path_parts": ["appdata", ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".config"],
        "suffixes": [
            ".env",
            ".env.*",
            ".env.local",
            ".env.development",
            ".env.production",
            ".env.staging",
            ".env.test",
            ".env.backup",
            ".env.old",
            ".env.sample",
            ".env.example",
            ".key",
            ".pem",
            ".pfx",
            ".p12",
            ".kdbx",
            ".ovpn",
        ],
        "file_names": ["id_rsa", "id_ed25519", "authorized_keys", "known_hosts", "credentials", "config.json"],
        "name_contains": [
            "secret",
            "token",
            "password",
            "apikey",
            "api_key",
            "private_key",
            ".env.",
        ],
    },
    "tool_registry": {
        "active_profile": "standard",
        "disabled_tools": [],
        "custom_profiles": {},
    },
}

# Abgeschaltete Einträge landen in policy.tool_registry.disabled_tools (Server: remove_tool).
LITE_TOGGLEABLE_TOOLS: tuple[tuple[str, str], ...] = (
    ("list_roots", "list_roots"),
    ("list_directory", "list_directory"),
    ("read_file", "read_file"),
    ("search_files", "search_files"),
    ("write_file", "write_file"),
    ("create_directory", "create_directory"),
    ("delete_path", "delete_path"),
)

MCC_SETTINGS_SNAPSHOT_VERSION = 1

_AUTH_MODE_HINTS_DE: dict[str, str] = {
    "none": "Kein OAuth am MCP-Endpunkt — nur in vertrauenswürdigen Umgebungen.",
    "bearer": "Bearer-Keys aus dem Keystore; Zuordnung über Client-Namen.",
    "github": "GitHub OAuth App: Public Base URL, Callback und App-Einstellungen müssen zusammenpassen.",
    "google": "Google OAuth — Redirect-URI und Provider-Daten müssen stimmen.",
    "oidc": "OIDC — Server benötigt u. a. MCP_OIDC_CONFIG_URL (siehe FastMCP-Doku).",
}


class GuardianControlCenter(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self._locale_menu_var = tk.StringVar(value="de")
        self._current_section = "Monitoring"
        self.geometry("1380x860")
        self._app_ready = False
        self._keystore_store: dict[str, str] | None = None
        self._master_password = ""

        self.server_proc = None
        self._mcp_server_log_fp: TextIO | None = None
        self.tunnel_proc = None
        self.server_start_time: datetime | None = None
        self.events = []
        self.suspicious = []
        self._disconnect_called = False
        self._activity_prev_suspicious_count = 0
        self.dark_mode_var = tk.BooleanVar(value=False)
        self.sections = {}
        self.nav_buttons = {}
        self._last_suspicious_count = 0
        self._health_job = None
        self._health_interval_min = tk.IntVar(value=5)
        self._health_enabled = tk.BooleanVar(value=True)
        self._timeout_enabled = tk.BooleanVar(value=False)
        self._timeout_minutes = tk.IntVar(value=60)
        self._timeout_warned = False
        self._last_activity_ts: datetime | None = None
        self._toast_health = tk.BooleanVar(value=True)
        self._toast_suspicious = tk.BooleanVar(value=True)
        self._toast_timeout_warn = tk.BooleanVar(value=True)
        self._adv_max_write = tk.IntVar(value=5000000)
        self._adv_search_prio = tk.BooleanVar(value=True)
        self._adv_path_norm = tk.BooleanVar(value=True)
        self._adv_delete_check = tk.BooleanVar(value=True)
        self._adv_auto_lock = tk.BooleanVar(value=False)
        self._adv_auto_lock_min = tk.IntVar(value=15)
        self._adv_log_retention = tk.BooleanVar(value=False)
        self._adv_log_retention_days = tk.IntVar(value=90)
        self._adv_geo_tracking = tk.BooleanVar(value=False)
        self._adv_rate_limit_var = tk.IntVar(value=60)
        self._pi_enabled = tk.BooleanVar(value=True)
        self._pi_scope = tk.StringVar(value="selective")
        self._pi_cat_write = tk.BooleanVar(value=True)
        self._pi_cat_read = tk.BooleanVar(value=False)
        self._pi_cat_exec = tk.BooleanVar(value=True)
        self._pi_interval_min = tk.IntVar(value=5)
        self._pi_include_keystore = tk.BooleanVar(value=True)
        self._suppress_pi_ui_events = False
        self._suppress_mode_trace = False
        self._nav_button_style_normal = "Nav.TButton"
        self._nav_button_style_active = "NavActive.TButton"
        self.last_transfer_stats = {
            "upload_total": 0,
            "download_total": 0,
            "upload_rate": 0.0,
            "download_rate": 0.0,
            "total": 0,
        }
        self._mon_filter_tool = tk.StringVar(value="")
        self._mon_filter_outcome = tk.StringVar(value="alle")
        self._mon_filter_search = tk.StringVar(value="")
        self._mon_time_minutes = tk.IntVar(value=0)
        self._mon_show_full_paths = tk.BooleanVar(value=False)
        self._suppress_mon_persist = False
        self._suppress_pub_url_persist = False
        self._policy_dirty = False
        self._suppress_policy_dirty = False
        self._tool_toggle_vars: dict[str, tk.BooleanVar] = {}
        self._tool_profile_var = tk.StringVar(value="standard")
        self._tool_custom_profiles: dict[str, dict[str, Any]] = {}
        self._oauth_secret_rotated_iso = ""

        self._ensure_dirs()
        _bootstrap_ui_locale_from_guardian_json()
        self._locale_menu_var.set(mcc_locale())
        self.title(t("app_title"))
        self._ensure_policy()
        if not self._run_unlock_flow():
            self._app_ready = False
            self.after(0, self.destroy)
            return
        self._app_ready = True
        self._master_password = ""
        self._build_ui()
        self._hydrate_oauth_from_keystore()
        self._apply_theme()
        self._load_guardian_ui_settings()
        self._bind_keyboard_shortcuts()
        self.load_policy_to_ui()
        self.refresh_monitor()
        self.after(150, self._maybe_first_run_wizard)
        self.after(3000, self._auto_refresh)
        self.after(1000, self._update_live_statusbar)
        # Erster Health-Check verzögert (nach manuellem Stack-/Server-Start sinnvoller)
        self.after(120_000, self._schedule_health_loop)
        self._schedule_timeout_loop()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _run_unlock_flow(self) -> bool:
        if not KEYSTORE_PATH.exists():
            return self._dialog_setup_master()
        return self._dialog_unlock()

    def _dialog_setup_master(self) -> bool:
        ok = {"v": False}

        def submit() -> None:
            p1 = pw1.get()
            p2 = pw2.get()
            if len(p1) < 12:
                messagebox.showerror("Master-Passwort", "Mindestens 12 Zeichen.", parent=top)
                return
            if p1 != p2:
                messagebox.showerror("Master-Passwort", "Eingaben stimmen nicht überein.", parent=top)
                return
            setup_keystore(p1)
            ok["v"] = True
            self._master_password = p1
            self._keystore_store = {}
            top.destroy()

        top = tk.Toplevel(self)
        top.title("Master-Passwort festlegen")
        top.grab_set()
        top.transient(self)
        f = ttk.Frame(top, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Erststart: Master-Passwort wählen (min. 12 Zeichen).").pack(anchor=tk.W)
        ttk.Label(f, text="Passwort:").pack(anchor=tk.W, pady=(8, 0))
        pw1 = ttk.Entry(f, width=40, show="*")
        pw1.pack(fill=tk.X)
        ttk.Label(f, text="Wiederholen:").pack(anchor=tk.W, pady=(6, 0))
        pw2 = ttk.Entry(f, width=40, show="*")
        pw2.pack(fill=tk.X)
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=10)
        ttk.Button(bf, text="OK", command=submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text="Beenden", command=top.destroy).pack(side=tk.RIGHT)
        top.protocol("WM_DELETE_WINDOW", top.destroy)
        top.wait_window(top)
        return ok["v"]

    def _dialog_unlock(self) -> bool:
        ok = {"v": False}

        def submit() -> None:
            pw = pw_entry.get()
            store = unlock_keystore(pw)
            if store is None:
                messagebox.showerror("Entsperren", "Falsches Passwort.", parent=top)
                return
            ok["v"] = True
            self._master_password = pw
            self._keystore_store = store
            top.destroy()

        top = tk.Toplevel(self)
        top.title(t("unlock_title"))
        top.grab_set()
        top.transient(self)
        f = ttk.Frame(top, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Master-Passwort:").pack(anchor=tk.W)
        pw_entry = ttk.Entry(f, width=40, show="*")
        pw_entry.pack(fill=tk.X, pady=6)
        pw_entry.focus_set()
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=10)
        ttk.Button(bf, text="OK", command=submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text="Beenden", command=top.destroy).pack(side=tk.RIGHT)
        top.bind("<Return>", lambda e: submit())
        top.protocol("WM_DELETE_WINDOW", top.destroy)
        top.wait_window(top)
        return ok["v"]

    def _require_master_password(self) -> str | None:
        result = {"pw": None}
        def submit():
            pw = pw_entry.get()
            store = unlock_keystore(pw)
            if store is None:
                messagebox.showerror("Passwort", "Falsches Passwort.", parent=top)
                return
            result["pw"] = pw
            self._keystore_store = store
            top.destroy()
        top = tk.Toplevel(self)
        top.title("Master-Passwort erforderlich")
        top.grab_set()
        top.transient(self)
        f = ttk.Frame(top, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Master-Passwort für Keystore-Operation:").pack(anchor=tk.W)
        pw_entry = ttk.Entry(f, width=40, show="*")
        pw_entry.pack(fill=tk.X, pady=6)
        pw_entry.focus_set()
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=10)
        ttk.Button(bf, text="OK", command=submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text="Abbrechen", command=top.destroy).pack(side=tk.RIGHT)
        top.bind("<Return>", lambda e: submit())
        top.protocol("WM_DELETE_WINDOW", top.destroy)
        top.wait_window(top)
        return result["pw"]

    def _require_master_password_confirm(self, title: str, prompt: str) -> bool:
        """True, wenn das Master-Passwort korrekt eingegeben wurde (z. B. für sicherheitskritische Aktionen)."""
        ok = {"v": False}

        def submit() -> None:
            pw = pw_entry.get()
            store = unlock_keystore(pw)
            if store is None:
                messagebox.showerror("Passwort", "Falsches Passwort.", parent=top)
                return
            self._keystore_store = store
            ok["v"] = True
            top.destroy()

        top = tk.Toplevel(self)
        top.title(title)
        top.grab_set()
        top.transient(self)
        f = ttk.Frame(top, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=prompt, wraplength=420).pack(anchor=tk.W)
        pw_entry = ttk.Entry(f, width=40, show="*")
        pw_entry.pack(fill=tk.X, pady=6)
        pw_entry.focus_set()
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=10)
        ttk.Button(bf, text="OK", command=submit).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text="Abbrechen", command=top.destroy).pack(side=tk.RIGHT)
        top.bind("<Return>", lambda e: submit())
        top.protocol("WM_DELETE_WINDOW", top.destroy)
        top.wait_window(top)
        return bool(ok["v"])

    def _ensure_dirs(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    def _maybe_first_run_wizard(self) -> None:
        """BUG-015: kurzer First-Run-Hinweis (Secure-by-Default)."""
        flag = CONFIG_DIR / ".mcc_first_run_ack"
        if flag.exists():
            return
        loc_codes = {"Deutsch": "de", "English": "en"}
        rev = {v: k for k, v in loc_codes.items()}

        top = tk.Toplevel(self)
        top.title(t("first_run_title"))
        top.geometry("560x460")
        top.grab_set()
        top.transient(self)
        fr = ttk.Frame(top, padding=10)
        fr.pack(fill=tk.BOTH, expand=True)

        locale_row = ttk.Frame(fr)
        locale_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(locale_row, text=t("first_run_locale_label")).pack(side=tk.LEFT, padx=(0, 8))
        loc_display = tk.StringVar(value=rev.get(mcc_locale(), "Deutsch"))
        loc_cb = ttk.Combobox(
            locale_row,
            textvariable=loc_display,
            values=("Deutsch", "English"),
            state="readonly",
            width=14,
        )
        loc_cb.pack(side=tk.LEFT)

        body = tk.Text(fr, wrap=tk.WORD, height=13, width=64)
        body.pack(fill=tk.BOTH, expand=True)
        body.insert("1.0", t("first_run_intro"))
        body.config(state=tk.DISABLED)
        agreed = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(fr, text=t("first_run_checkbox"), variable=agreed)
        chk.pack(anchor=tk.W, pady=(8, 4))

        bf = ttk.Frame(fr)
        bf.pack(fill=tk.X, pady=8)

        def cont() -> None:
            if not agreed.get():
                messagebox.showwarning(t("first_run_title"), t("first_run_checkbox"), parent=top)
                return
            code = loc_codes.get(loc_display.get(), "de")
            set_ui_locale(code)
            self._locale_menu_var.set(code)
            self._save_guardian_ui_settings()
            try:
                flag.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
            except OSError:
                pass
            top.destroy()
            self._reapply_visible_locale()

        cont_btn = ttk.Button(bf, text=t("first_run_continue"), command=cont)
        cont_btn.pack(side=tk.RIGHT)

        def _apply_wizard_locale(_event: object | None = None) -> None:
            code = loc_codes.get(loc_display.get(), "de")
            set_ui_locale(code)
            top.title(t("first_run_title"))
            body.config(state=tk.NORMAL)
            body.delete("1.0", tk.END)
            body.insert("1.0", t("first_run_intro"))
            body.config(state=tk.DISABLED)
            chk.config(text=t("first_run_checkbox"))
            cont_btn.config(text=t("first_run_continue"))

        loc_cb.bind("<<ComboboxSelected>>", _apply_wizard_locale)

    def _ensure_policy(self) -> None:
        if not POLICY_FILE.exists():
            POLICY_FILE.write_text(json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2), encoding="utf-8")
        if not EXPORT_COUNTER_FILE.exists():
            EXPORT_COUNTER_FILE.write_text(json.dumps({"next": 1}, ensure_ascii=False, indent=2), encoding="utf-8")

    def _format_bytes(self, size: int) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(max(size, 0))
        idx = 0
        while value >= 1024 and idx < len(units) - 1:
            value /= 1024
            idx += 1
        return f"{value:.1f} {units[idx]}"

    def _bytes_per_sec_to_str(self, rate: float) -> str:
        return f"{self._format_bytes(int(rate))}/s"

    def _get_export_sequence(self) -> int:
        try:
            raw = json.loads(EXPORT_COUNTER_FILE.read_text(encoding="utf-8"))
            current = int(raw.get("next", 1))
        except Exception:
            current = 1

        if current < 1:
            current = 1

        EXPORT_COUNTER_FILE.write_text(json.dumps({"next": current + 1}, ensure_ascii=False, indent=2), encoding="utf-8")
        return current

    def _estimate_transfer_bytes(self, event: dict) -> tuple[int, int]:
        args = event.get("args") or {}
        if not isinstance(args, dict):
            return 0, 0

        upload = 0
        download = 0
        tool = str(event.get("tool", ""))

        if tool in {"read_file", "list_directory", "search_files", "list_roots", "policy_snapshot"}:
            download += int(args.get("returned_bytes", 0) or 0)
            download += int(args.get("response_bytes", 0) or 0)

        if tool == "write_file":
            upload += int(args.get("bytes", 0) or 0)
            upload += int(args.get("chars", 0) or 0)

        return upload, download

    def _compute_transfer_stats(self, events: list[dict]) -> dict:
        now = datetime.now(timezone.utc)
        upload_total = 0
        download_total = 0
        upload_60s = 0
        download_60s = 0

        for event in events:
            upload, download = self._estimate_transfer_bytes(event)
            upload_total += upload
            download_total += download

            event_ts = self._parse_ts(str(event.get("ts", "")))
            if (now - event_ts).total_seconds() <= 60:
                upload_60s += upload
                download_60s += download

        return {
            "upload_total": upload_total,
            "download_total": download_total,
            "upload_rate": upload_60s / 60.0,
            "download_rate": download_60s / 60.0,
            "total": upload_total + download_total,
        }

    def _build_ui(self) -> None:
        self._build_menu()

        top = ttk.Frame(self, padding=10)
        top.pack(fill=tk.X)

        self.status_var = tk.StringVar(value=t("status_ready"))
        self.url_var = tk.StringVar(value=f"{t('url_tunnel_prefix')} -")

        ttk.Label(top, textvariable=self.status_var).pack(side=tk.LEFT)
        self._tunnel_url_label = tk.Label(
            top,
            textvariable=self.url_var,
            fg="#1a5f9e",
            cursor="hand2",
            font=("Segoe UI", 9, "underline"),
        )
        self._tunnel_url_label.pack(side=tk.LEFT, padx=20)
        self._tunnel_url_label.bind("<Button-1>", lambda _e: self._switch_section("Betrieb"))
        _SimpleTooltip(self, self._tunnel_url_label, "Zum Tab „Betrieb“ wechseln (Server-Steuerung, Logs).")

        self._btn_stack_start = ttk.Button(top, text=t("stack_start"), command=self.start_stack)
        self._btn_stack_start.pack(side=tk.RIGHT, padx=4)
        _SimpleTooltip(self, self._btn_stack_start, "MCP-Server starten (und ggf. Selbsttest).")
        self._btn_stack_stop = ttk.Button(top, text=t("stack_stop"), command=self.stop_stack)
        self._btn_stack_stop.pack(side=tk.RIGHT, padx=4)
        _SimpleTooltip(self, self._btn_stack_stop, "MCP-Server stoppen.")
        self._btn_export_toolbar = ttk.Button(top, text=t("m_export_now"), command=self.export_now)
        self._btn_export_toolbar.pack(side=tk.RIGHT, padx=4)
        _SimpleTooltip(
            self,
            self._btn_export_toolbar,
            "Sofortiger Export der Session-Daten (JSON/Logs) ohne Trennung der Verbindung.",
        )
        self._btn_disc_toolbar = ttk.Button(top, text=t("m_disconnect"), command=self.disconnect_and_export)
        self._btn_disc_toolbar.pack(side=tk.RIGHT, padx=4)
        _SimpleTooltip(
            self,
            self._btn_disc_toolbar,
            "Verbindung beenden und anschließend exportieren (sauberer Abschluss).",
        )
        sb = tk.Frame(self, relief=tk.GROOVE, bd=1)
        sb.pack(fill=tk.X, padx=10, pady=(0, 4))
        self.uptime_var = tk.StringVar(value="Uptime: —")
        self.upload_session_var = tk.StringVar(value="Upload Session: 0 B")
        self.download_session_var = tk.StringVar(value="Download Session: 0 B")
        tk.Label(sb, textvariable=self.uptime_var, width=28, anchor="w", font=("Consolas", 10)).pack(side=tk.LEFT, padx=8, pady=4)
        ttk.Separator(sb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=2)
        tk.Label(sb, textvariable=self.upload_session_var, width=32, anchor="w", font=("Consolas", 10)).pack(side=tk.LEFT, padx=4, pady=4)
        ttk.Separator(sb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=2)
        tk.Label(sb, textvariable=self.download_session_var, width=32, anchor="w", font=("Consolas", 10)).pack(side=tk.LEFT, padx=4, pady=4)
        ttk.Separator(sb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=2)
        self.activity_label = tk.Label(
            sb,
            text=t("activity_stopped"),
            width=18,
            anchor="center",
            font=("Consolas", 10, "bold"),
            bg="#888888",
            fg="white",
            padx=8,
            pady=4,
        )
        self.activity_label.pack(side=tk.LEFT, padx=4, pady=2)

        body = ttk.Frame(self, padding=(10, 0, 10, 10))
        body.pack(fill=tk.BOTH, expand=True)

        nav = ttk.Frame(body)
        nav.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        content = ttk.Frame(body)
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.sections = {
            "Monitoring": ttk.Frame(content),
            "Policy": ttk.Frame(content),
            "Auth/Connector": ttk.Frame(content),
            "Blocklist": ttk.Frame(content),
            "Betrieb": ttk.Frame(content),
            "Erweitert": ttk.Frame(content),
            "Hilfe": ttk.Frame(content),
        }

        for frame in self.sections.values():
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        nav_style = ttk.Style(self)
        try:
            nav_style.configure(self._nav_button_style_normal, padding=(4, 2))
            nav_style.configure(self._nav_button_style_active, padding=(4, 2), background="#b3d7ff")
        except Exception:
            pass

        for name in [
            "Monitoring", "Policy", "Auth/Connector", "Blocklist", "Betrieb",
            "Erweitert", "Hilfe",
        ]:
            btn = ttk.Button(
                nav,
                text=self._section_label(name),
                width=18,
                style=self._nav_button_style_normal,
                command=lambda n=name: self._switch_section(n),
            )
            btn.pack(fill=tk.X, pady=2)
            self.nav_buttons[name] = btn

        self._build_monitor_tab(self.sections["Monitoring"])
        self._build_policy_tab(self.sections["Policy"])
        self._build_connector_tab(self.sections["Auth/Connector"])
        self._build_blocklist_tab(self.sections["Blocklist"])
        self._build_ops_tab(self.sections["Betrieb"])
        self._build_advanced_tab(self.sections["Erweitert"])
        self._build_help_tab(self.sections["Hilfe"])
        self._switch_section("Monitoring")
        shortcuts = [
            ("Monitoring", "1"),
            ("Policy", "2"),
            ("Auth/Connector", "3"),
            ("Blocklist", "4"),
            ("Betrieb", "5"),
            ("Erweitert", "6"),
            ("Hilfe", "7"),
        ]
        for name, key in shortcuts:
            self.bind(f"<Control-Key-{key}>", lambda e, n=name: self._switch_section(n))

    def _section_label(self, name: str) -> str:
        key = _SECTION_LABEL_KEYS.get(name)
        return t(key) if key else name

    def _set_ui_locale(self, code: str) -> None:
        c = str(code).strip().lower()
        if c not in ("de", "en"):
            return
        set_ui_locale(c)
        self._locale_menu_var.set(c)
        self._save_guardian_ui_settings()
        self._reapply_visible_locale()

    def _reapply_visible_locale(self) -> None:
        self._sync_window_title()
        self._build_menu()
        for name, btn in self.nav_buttons.items():
            try:
                btn.config(text=self._section_label(name))
            except Exception:
                pass
        if hasattr(self, "_btn_stack_start"):
            self._btn_stack_start.config(text=t("stack_start"))
            self._btn_stack_stop.config(text=t("stack_stop"))
        if hasattr(self, "_btn_export_toolbar"):
            self._btn_export_toolbar.config(text=t("m_export_now"))
            self._btn_disc_toolbar.config(text=t("m_disconnect"))
        if hasattr(self, "help_text"):
            self._refresh_help_text()
        cur = getattr(self, "_current_section", "Monitoring")
        self._switch_section(cur)

    def _build_menu(self) -> None:
        menu = tk.Menu(self)
        self.config(menu=menu)

        datei = tk.Menu(menu, tearoff=0)
        datei.add_command(label=t("m_export_now"), command=self.export_now, accelerator=t("acc_e"))
        datei.add_command(label=t("m_disconnect"), command=self.disconnect_and_export)
        datei.add_separator()
        datei.add_command(label=t("m_save_policy"), command=self.save_policy_from_ui, accelerator=t("acc_s"))
        datei.add_separator()
        datei.add_command(label=t("m_snapshot_export"), command=self._export_settings_snapshot)
        datei.add_command(label=t("m_snapshot_import"), command=self._import_settings_snapshot)
        datei.add_separator()
        datei.add_command(label=t("m_change_master"), command=self._change_master_password_dialog)
        datei.add_command(label=t("m_keystore_export"), command=self._export_keystore_plaintext_dialog)
        datei.add_separator()
        datei.add_command(label=t("m_quit"), command=self._on_close, accelerator=t("acc_q"))
        menu.add_cascade(label=t("menu_file"), menu=datei)

        ansicht = tk.Menu(menu, tearoff=0)
        lang = tk.Menu(ansicht, tearoff=0)
        lang.add_radiobutton(
            label=t("m_lang_de"),
            variable=self._locale_menu_var,
            value="de",
            command=lambda: self._set_ui_locale("de"),
        )
        lang.add_radiobutton(
            label=t("m_lang_en"),
            variable=self._locale_menu_var,
            value="en",
            command=lambda: self._set_ui_locale("en"),
        )
        ansicht.add_cascade(label=t("m_lang"), menu=lang)
        ansicht.add_separator()
        ansicht.add_checkbutton(label=t("m_dark"), variable=self.dark_mode_var, command=self._apply_theme)
        ansicht.add_separator()
        ansicht.add_command(label=self._section_label("Monitoring"), command=lambda: self._switch_section("Monitoring"))
        ansicht.add_command(label=self._section_label("Policy"), command=lambda: self._switch_section("Policy"))
        ansicht.add_command(label=self._section_label("Auth/Connector"), command=lambda: self._switch_section("Auth/Connector"))
        ansicht.add_command(label=self._section_label("Blocklist"), command=lambda: self._switch_section("Blocklist"))
        ansicht.add_command(label=self._section_label("Betrieb"), command=lambda: self._switch_section("Betrieb"))
        ansicht.add_command(label=self._section_label("Erweitert"), command=lambda: self._switch_section("Erweitert"))
        ansicht.add_command(label=self._section_label("Hilfe"), command=lambda: self._switch_section("Hilfe"))
        menu.add_cascade(label=t("menu_view"), menu=ansicht)

        hilfe = tk.Menu(menu, tearoff=0)
        hilfe.add_command(label=t("m_help_show"), command=lambda: self._switch_section("Hilfe"))
        hilfe.add_command(label=t("m_help_save"), command=self._save_help_file)
        hilfe.add_separator()
        hilfe.add_command(label=t("m_access_log"), command=self._open_today_access_log)
        hilfe.add_separator()
        hilfe.add_command(label=t("m_about"), command=self._show_about)
        menu.add_cascade(label=t("menu_help"), menu=hilfe)

    def _switch_section(self, name: str) -> None:
        frame = self.sections.get(name)
        if not frame:
            return
        frame.tkraise()
        self._current_section = name
        self.status_var.set(t("status_section_fmt").format(section=self._section_label(name)))
        for nav_name, btn in self.nav_buttons.items():
            try:
                btn.configure(
                    style=self._nav_button_style_active if nav_name == name else self._nav_button_style_normal
                )
            except Exception:
                pass

    def _apply_theme(self) -> None:
        dark = self.dark_mode_var.get()
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        if dark:
            bg = "#1e1e1e"
            fg = "#f2f2f2"
            entry_bg = "#2b2b2b"
            self.configure(bg=bg)
            style.configure("TFrame", background=bg)
            style.configure("TLabelframe", background=bg, foreground=fg)
            style.configure("TLabelframe.Label", background=bg, foreground=fg)
            style.configure("TLabel", background=bg, foreground=fg)
            style.configure("TButton", background="#2b2b2b", foreground=fg)
            style.configure("TEntry", fieldbackground=entry_bg, foreground=fg)
            style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg)
            style.map("TButton", background=[("active", "#333333")])
            text_bg = "#252526"
            text_fg = "#f2f2f2"
        else:
            bg = "#f0f0f0"
            fg = "#111111"
            self.configure(bg=bg)
            style.configure("TFrame", background=bg)
            style.configure("TLabelframe", background=bg, foreground=fg)
            style.configure("TLabelframe.Label", background=bg, foreground=fg)
            style.configure("TLabel", background=bg, foreground=fg)
            style.configure("TButton", background="#e6e6e6", foreground=fg)
            style.configure("TEntry", fieldbackground="#ffffff", foreground="#000000")
            style.configure("TCombobox", fieldbackground="#ffffff", foreground="#000000")
            text_bg = "#ffffff"
            text_fg = "#111111"

        for widget_name in [
            "all_tree", "sus_tree", "blocklist_tree", "ops_log", "help_text", "blocklist_text", "roots_txt", "write_allow_txt", "write_deny_txt",
            "dir_names_txt", "path_parts_txt", "suffixes_txt", "file_names_txt", "name_contains_txt", "adv_canvas",
        ]:
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            try:
                widget.configure(bg=text_bg, fg=text_fg, insertbackground=text_fg)
            except Exception:
                pass
        link_fg = "#6ab0f5" if dark else "#1a5f9e"
        for link_name in ("_tunnel_url_label", "_mon_audit_log_link", "_conn_audit_log_link"):
            w = getattr(self, link_name, None)
            if w is not None:
                try:
                    w.config(fg=link_fg)
                except Exception:
                    pass

    def _show_about(self) -> None:
        messagebox.showinfo(t("about_menu"), t("about_body"))

    def _build_monitor_tab(self, tab: ttk.Frame) -> None:
        summary = ttk.Frame(tab, padding=8)
        summary.pack(fill=tk.X)
        self.summary_var = tk.StringVar(value="")
        ttk.Label(summary, textvariable=self.summary_var).pack(anchor=tk.W)

        self.traffic_var = tk.StringVar(value="Transfer: Senden 0 B/s | Empfangen 0 B/s | Gesamt 0 B")
        ttk.Label(summary, textvariable=self.traffic_var).pack(anchor=tk.W, pady=(2, 0))
        mon_links = ttk.Frame(summary)
        mon_links.pack(anchor=tk.W, pady=(4, 0))
        self._mon_audit_log_link = tk.Label(
            mon_links,
            text="Access-Log (Audit, JSONL) öffnen",
            fg="#1a5f9e",
            cursor="hand2",
            font=("Segoe UI", 9, "underline"),
        )
        self._mon_audit_log_link.pack(side=tk.LEFT)
        self._mon_audit_log_link.bind("<Button-1>", lambda _e: self._open_today_access_log())
        _SimpleTooltip(self, self._mon_audit_log_link, "Öffnet die heutige mcp_access_*.jsonl im Standardprogramm.")

        filt = ttk.LabelFrame(tab, text="Filter", padding=6)
        filt.pack(fill=tk.X, padx=8, pady=(0, 4))
        r1 = ttk.Frame(filt)
        r1.pack(fill=tk.X)
        ttk.Label(r1, text="Tool (Teilstring):").pack(side=tk.LEFT)
        ttk.Entry(r1, textvariable=self._mon_filter_tool, width=18).pack(side=tk.LEFT, padx=4)
        ttk.Label(r1, text="Ergebnis:").pack(side=tk.LEFT, padx=(12, 0))
        ttk.Combobox(
            r1, textvariable=self._mon_filter_outcome, width=12, state="readonly",
            values=("alle", "ok", "denied"),
        ).pack(side=tk.LEFT, padx=4)
        ttk.Label(r1, text="Suche:").pack(side=tk.LEFT, padx=(12, 0))
        ttk.Entry(r1, textvariable=self._mon_filter_search, width=28).pack(side=tk.LEFT, padx=4)
        ttk.Label(r1, text="Zeitfenster (Min):").pack(side=tk.LEFT, padx=(12, 0))
        ttk.Spinbox(r1, from_=0, to=24 * 60, width=6, textvariable=self._mon_time_minutes).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(r1, text="Pfade voll anzeigen", variable=self._mon_show_full_paths).pack(side=tk.LEFT, padx=12)
        ttk.Button(r1, text="Anwenden", command=self.refresh_monitor).pack(side=tk.RIGHT, padx=4)

        def _mon_reset_filters() -> None:
            self._suppress_mon_persist = True
            self._mon_filter_tool.set("")
            self._mon_filter_outcome.set("alle")
            self._mon_filter_search.set("")
            self._mon_time_minutes.set(0)
            self._mon_show_full_paths.set(False)
            self._suppress_mon_persist = False
            self._save_guardian_ui_settings()
            self.refresh_monitor()

        def _mon_only_denied() -> None:
            self._mon_filter_outcome.set("denied")
            self.refresh_monitor()

        r2 = ttk.Frame(filt)
        r2.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(r2, text="Filter zurücksetzen", command=_mon_reset_filters).pack(side=tk.LEFT, padx=2)
        ttk.Button(r2, text="Nur denied", command=_mon_only_denied).pack(side=tk.LEFT, padx=2)

        def _persist_mon(*_a: object) -> None:
            if getattr(self, "_suppress_mon_persist", False):
                return
            self._save_guardian_ui_settings()

        for v in (
            self._mon_filter_tool,
            self._mon_filter_outcome,
            self._mon_filter_search,
            self._mon_time_minutes,
            self._mon_show_full_paths,
        ):
            v.trace_add("write", _persist_mon)

        split = ttk.Panedwindow(tab, orient=tk.VERTICAL)
        split.pack(fill=tk.BOTH, expand=True)

        top_frame = ttk.Labelframe(split, text="Alle Zugriffe", padding=6)
        bot_frame = ttk.Labelframe(split, text="Verdächtige Zugriffe (Layer-2-Heuristik)", padding=6)
        split.add(top_frame, weight=3)
        split.add(bot_frame, weight=2)

        cols_all = ("ts", "outcome", "tool", "client", "ip", "land", "ua", "path", "reason")
        all_titles = {
            "ts": "Zeit (UTC)",
            "outcome": "Ergebnis",
            "tool": "Tool",
            "client": "Client",
            "ip": "Client-IP",
            "land": "Land",
            "ua": "User-Agent",
            "path": "Pfad",
            "reason": "Grund",
        }
        all_wrap = ttk.Frame(top_frame)
        all_wrap.pack(fill=tk.BOTH, expand=True)
        sb_all = ttk.Scrollbar(all_wrap, orient="vertical")
        sb_all.pack(side=tk.RIGHT, fill=tk.Y)
        self.all_tree = ttk.Treeview(all_wrap, columns=cols_all, show="headings", yscrollcommand=sb_all.set)
        for col, width in {
            "ts": 200,
            "outcome": 110,
            "tool": 140,
            "client": 200,
            "ip": 140,
            "land": 52,
            "ua": 200,
            "path": 320,
            "reason": 220,
        }.items():
            self.all_tree.heading(col, text=all_titles.get(col, col))
            stretch = col in ("path", "ua", "reason", "client")
            self.all_tree.column(col, width=width, minwidth=60, anchor=tk.W, stretch=stretch)
        self.all_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_all.config(command=self.all_tree.yview)

        cols_sus = ("ts", "tool", "client", "ip", "path", "meta")
        sus_titles = {
            "ts": "Zeit (UTC)",
            "tool": "Tool",
            "client": "Client",
            "ip": "Client-IP",
            "path": "Pfad",
            "meta": "Indikatoren (Heuristik)",
        }
        sus_wrap = ttk.Frame(bot_frame)
        sus_wrap.pack(fill=tk.BOTH, expand=True)
        sb_sus = ttk.Scrollbar(sus_wrap, orient="vertical")
        sb_sus.pack(side=tk.RIGHT, fill=tk.Y)
        self.sus_tree = ttk.Treeview(sus_wrap, columns=cols_sus, show="headings", yscrollcommand=sb_sus.set)
        for col, width in {
            "ts": 200,
            "tool": 130,
            "client": 200,
            "ip": 140,
            "path": 300,
            "meta": 380,
        }.items():
            self.sus_tree.heading(col, text=sus_titles.get(col, col))
            stretch = col in ("path", "meta")
            self.sus_tree.column(col, width=width, minwidth=60, anchor=tk.W, stretch=stretch)
        self.sus_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_sus.config(command=self.sus_tree.yview)

    def _textarea(self, parent, label: str, height: int = 4, *, mark_dirty: bool = True) -> tk.Text:
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=False, pady=3)
        ttk.Label(frame, text=label).pack(anchor=tk.W)
        inner = ttk.Frame(frame)
        inner.pack(fill=tk.X)
        sb = ttk.Scrollbar(inner, orient="vertical")
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        txt = tk.Text(inner, height=height, yscrollcommand=sb.set)
        txt.pack(side=tk.LEFT, fill=tk.X, expand=True)
        sb.config(command=txt.yview)
        if mark_dirty:
            txt.bind("<KeyRelease>", lambda _e: self._mark_policy_dirty())
        return txt

    def _path_list_editor(
        self,
        parent: ttk.Frame,
        label: str,
        height: int = 4,
        *,
        on_extra_key: Callable[[], None] | None = None,
    ) -> tk.Text:
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=False, pady=3)
        hdr = ttk.Frame(frame)
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text=label).pack(side=tk.LEFT)

        def _browse_add() -> None:
            p = filedialog.askdirectory(parent=self)
            if not p:
                return
            txt.insert(tk.END, p.replace("/", os.sep) + "\n")
            self._mark_policy_dirty()

        ttk.Button(hdr, text="+ Ordner", width=11, command=_browse_add).pack(side=tk.RIGHT)
        inner = ttk.Frame(frame)
        inner.pack(fill=tk.X)
        sb = ttk.Scrollbar(inner, orient="vertical")
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        txt = tk.Text(inner, height=height, yscrollcommand=sb.set)
        txt.pack(side=tk.LEFT, fill=tk.X, expand=True)
        sb.config(command=txt.yview)

        def _on_key(_e: object) -> None:
            self._mark_policy_dirty()
            if on_extra_key:
                on_extra_key()

        txt.bind("<KeyRelease>", _on_key)
        return txt

    def _mark_policy_dirty(self) -> None:
        if getattr(self, "_suppress_policy_dirty", False):
            return
        if self._policy_dirty:
            return
        self._policy_dirty = True
        self._sync_window_title()

    def _clear_policy_dirty(self) -> None:
        self._policy_dirty = False
        self._sync_window_title()

    def _sync_window_title(self) -> None:
        base = t("app_title")
        self.title(base + (" *" if self._policy_dirty else ""))

    def _build_policy_tab(self, tab: ttk.Frame) -> None:
        canvas = tk.Canvas(tab, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        container = ttk.Frame(canvas, padding=10)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        container_id = canvas.create_window((0, 0), window=container, anchor="nw")
        
        def _configure_canvas(event):
            canvas.itemconfig(container_id, width=event.width)
            
        def _configure_container(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            
        canvas.bind("<Configure>", _configure_canvas)
        container.bind("<Configure>", _configure_container)

        row1 = ttk.Frame(container)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="Modus:").pack(side=tk.LEFT)
        self.mode_var = tk.StringVar(value="read_only")
        mode_box = ttk.Combobox(row1, textvariable=self.mode_var, values=["read_only", "read_write"], state="readonly", width=18)
        mode_box.pack(side=tk.LEFT, padx=8)

        self._policy_risk_label = tk.Label(row1, text="", fg="red", font=("Segoe UI", 10, "bold"))
        self._policy_risk_label.pack(side=tk.LEFT, padx=6)
        self.mode_var.trace_add("write", lambda *_: self._on_mode_var_changed())

        ttk.Label(row1, text="MCP Port:").pack(side=tk.LEFT, padx=(20, 0))
        self.port_var = tk.StringVar(value="8766")
        ttk.Entry(row1, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=6)

        ttk.Label(row1, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(row1, textvariable=self.host_var, width=14).pack(side=tk.LEFT, padx=6)

        ttk.Label(row1, text="Pfad:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar(value="/mcp")
        ttk.Entry(row1, textvariable=self.path_var, width=10).pack(side=tk.LEFT, padx=6)
        for _pv in (self.port_var, self.host_var, self.path_var):
            _pv.trace_add("write", lambda *_a: self._mark_policy_dirty())

        self.roots_txt = self._path_list_editor(
            container,
            "Erlaubte Roots (eine Zeile pro Pfad)",
            4,
            on_extra_key=self._update_policy_risk,
        )
        self.write_allow_txt = self._path_list_editor(container, "Write Allow Paths (optional, eine Zeile pro Prefix)", 3)
        self.write_deny_txt = self._path_list_editor(container, "Write Deny Paths (optional, eine Zeile pro Prefix)", 3)

        tf = ttk.LabelFrame(
            container,
            text="MCP-Tools (deaktiviert = nach Server-Neustart nicht registriert; policy_snapshot bleibt immer aktiv)",
            padding=8,
        )
        tf.pack(fill=tk.X, pady=6)
        self._tool_toggle_vars.clear()
        ncols = 4
        for i, (name, de_label) in enumerate(LITE_TOGGLEABLE_TOOLS):
            var = tk.BooleanVar(value=True)
            self._tool_toggle_vars[name] = var
            r, c = divmod(i, ncols)
            ttk.Checkbutton(tf, text=de_label, variable=var, command=self._mark_policy_dirty).grid(
                row=r, column=c, sticky=tk.W, padx=8, pady=2
            )
        last_row = (len(LITE_TOGGLEABLE_TOOLS) + ncols - 1) // ncols
        ttk.Label(
            tf,
            text="Ausgeschaltete Tools werden per remove_tool entfernt — MCP neu starten.",
            foreground="#555",
        ).grid(row=last_row, column=0, columnspan=ncols, sticky=tk.W, pady=(8, 0))
        pr = ttk.Frame(tf)
        pr.grid(row=last_row + 1, column=0, columnspan=ncols, sticky=tk.W, pady=(10, 0))
        ttk.Label(pr, text="Profil:").pack(side=tk.LEFT, padx=(0, 6))
        self._tool_profile_combo = ttk.Combobox(pr, textvariable=self._tool_profile_var, width=24, state="readonly")
        self._tool_profile_combo.pack(side=tk.LEFT, padx=4)
        ttk.Button(pr, text="Profil laden", command=self._tool_profile_apply).pack(side=tk.LEFT, padx=6)
        ttk.Button(pr, text="Speichern unter …", command=self._tool_profile_save_as).pack(side=tk.LEFT, padx=4)

        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, pady=6)
        ttk.Button(btn_frame, text="Policy laden", command=self.load_policy_to_ui).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Auf Standard setzen", command=self.reset_policy_defaults).pack(side=tk.LEFT, padx=4)
        _btn_pol_save = ttk.Button(btn_frame, text="Policy speichern", command=self.save_policy_from_ui)
        _btn_pol_save.pack(side=tk.LEFT, padx=4)
        _SimpleTooltip(
            self,
            _btn_pol_save,
            "Policy in config/mcp_policy.json schreiben (Tastenkürzel: Strg+S im Menü Datei).",
        )

    def _update_policy_risk(self) -> None:
        """S-03: Rotes Risiko-Label bei read_write + Laufwerk-Root."""
        import re
        mode = self.mode_var.get()
        if mode != "read_write":
            self._policy_risk_label.config(text="")
            return
        roots = self.roots_txt.get("1.0", tk.END).strip().splitlines()
        has_drive_root = any(re.match(r'^[A-Za-z]:[/\\]?$', r.strip()) for r in roots if r.strip())
        if has_drive_root:
            self._policy_risk_label.config(text="KRITISCH: read_write + Laufwerk-Root!")
        else:
            self._policy_risk_label.config(text="")

    def _on_mode_var_changed(self) -> None:
        self._update_policy_risk()
        if getattr(self, "_suppress_mode_trace", False):
            return
        if self.mode_var.get() == "read_write":
            if not messagebox.askyesno(
                "Schreibmodus (read_write)",
                "read_write erlaubt Schreibzugriffe gemäß Policy (write_allow_paths).\n\nFortfahren?",
                parent=self,
            ):
                self._suppress_mode_trace = True
                self.mode_var.set("read_only")
                self._suppress_mode_trace = False
                return
        self._mark_policy_dirty()

    def _build_connector_tab(self, tab: ttk.Frame) -> None:
        container = ttk.Frame(tab, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(container, text="Auth & Connector Einstellungen", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # --- Server OAuth (GitHub App) ---
        oauth_frame = ttk.LabelFrame(container, text="GitHub OAuth App (für MCP-Server)", padding=8)
        oauth_frame.pack(fill=tk.X, expand=False, pady=6)

        oauth_row1 = ttk.Frame(oauth_frame)
        oauth_row1.pack(fill=tk.X, pady=2)
        ttk.Label(oauth_row1, text="Auth Mode").pack(side=tk.LEFT)
        self.auth_mode_var = tk.StringVar(value="github")
        ttk.Combobox(
            oauth_row1, textvariable=self.auth_mode_var,
            values=["none", "bearer", "github", "google", "oidc"], width=14, state="readonly",
        ).pack(side=tk.LEFT, padx=6)

        ttk.Label(oauth_row1, text="Public Base URL").pack(side=tk.LEFT, padx=(20, 0))
        self.public_url_var = tk.StringVar(value="")
        _pub_entry = ttk.Entry(oauth_row1, textvariable=self.public_url_var, width=52)
        _pub_entry.pack(side=tk.LEFT, padx=6)
        _SimpleTooltip(
            self,
            _pub_entry,
            "Öffentliche Basis-URL (z. B. Cloudflare-Tunnel), ohne abschließenden Slash. "
            "Wird in config/guardian_ui.json gespeichert und beim Start wieder geladen.",
        )
        ttk.Button(
            oauth_row1,
            text="URL speichern",
            command=self._save_public_base_url_ui,
        ).pack(side=tk.LEFT, padx=(4, 0))

        self._auth_mode_hint_var = tk.StringVar(value="")
        auth_hint = ttk.Label(
            oauth_frame,
            textvariable=self._auth_mode_hint_var,
            foreground="#555",
            wraplength=900,
        )
        auth_hint.pack(anchor=tk.W, pady=(4, 2))
        self.auth_mode_var.trace_add("write", lambda *_a: self._update_auth_mode_hint())
        self._update_auth_mode_hint()

        oauth_row2 = ttk.Frame(oauth_frame)
        oauth_row2.pack(fill=tk.X, pady=2)
        oauth_row2.columnconfigure(1, weight=1)
        ttk.Label(oauth_row2, text="Client ID").grid(row=0, column=0, sticky=tk.W, padx=(0, 8))
        self.client_id_var = tk.StringVar(value="")
        self._client_id_entry = ttk.Entry(oauth_row2, textvariable=self.client_id_var, width=45, show="*")
        self._client_id_entry.grid(row=0, column=1, sticky=tk.EW, padx=6)
        self._client_id_visible = False

        def _toggle_client_id() -> None:
            self._client_id_visible = not self._client_id_visible
            self._client_id_entry.config(show="" if self._client_id_visible else "*")

        ttk.Button(oauth_row2, text="\U0001F441", width=3, command=_toggle_client_id).grid(row=0, column=2, padx=(4, 0))

        ttk.Label(oauth_row2, text="Client Secret").grid(row=1, column=0, sticky=tk.NW, padx=(0, 8), pady=(8, 0))
        self.client_secret_var = tk.StringVar(value="")
        self._client_secret_entry = ttk.Entry(oauth_row2, textvariable=self.client_secret_var, show="*", width=45)
        self._client_secret_entry.grid(row=1, column=1, sticky=tk.EW, padx=6, pady=(8, 0))
        self._client_secret_visible = False
        self._client_secret_len_lbl = ttk.Label(oauth_row2, text="", width=6)
        self._client_secret_len_lbl.grid(row=1, column=2, sticky=tk.W, padx=2, pady=(8, 0))

        def _upd_secret_len(*_a: object) -> None:
            n = len(self.client_secret_var.get())
            self._client_secret_len_lbl.config(text=f"({n})" if n else "")

        self.client_secret_var.trace_add("write", _upd_secret_len)

        def _toggle_client_secret() -> None:
            self._client_secret_visible = not self._client_secret_visible
            self._client_secret_entry.config(show="" if self._client_secret_visible else "*")

        ttk.Button(oauth_row2, text="\U0001F441", width=3, command=_toggle_client_secret).grid(
            row=1, column=3, padx=(4, 0), pady=(8, 0)
        )

        self._oauth_rot_hint_lbl = ttk.Label(
            oauth_row2,
            text="",
            foreground="#555",
            font=("Segoe UI", 8),
            wraplength=880,
        )
        self._oauth_rot_hint_lbl.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(6, 0))
        self._sync_oauth_rotation_label()

        oauth_save_row = ttk.Frame(oauth_frame)
        oauth_save_row.pack(fill=tk.X, pady=4)
        ttk.Button(
            oauth_save_row,
            text="OAuth im Keystore speichern",
            command=self._save_oauth_to_keystore,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(
            oauth_save_row,
            text=(
                "Hinweis: Keystore speichert nur auf der Platte — der laufende MCP-Server bekommt OAuth-Daten "
                "einmalig beim Server-Start (temporäre Datei). Nach erneuertem Secret: Server neu starten (oder beim Speichern "
                "den angebotenen Neustart wählen)."
            ),
            wraplength=900,
            foreground="#555",
        ).pack(side=tk.LEFT, anchor=tk.W)

        oauth_row3 = ttk.Frame(oauth_frame)
        oauth_row3.pack(fill=tk.X, pady=2)
        ttk.Label(oauth_row3, text="Scopes (comma)").pack(side=tk.LEFT)
        self.scopes_var = tk.StringVar(value="read:user,user:email")
        ttk.Entry(oauth_row3, textvariable=self.scopes_var, width=45).pack(side=tk.LEFT, padx=6)

        oauth_row4 = ttk.Frame(oauth_frame)
        oauth_row4.pack(fill=tk.X, pady=2)
        ttk.Label(oauth_row4, text="Callback URL (in GitHub)").pack(side=tk.LEFT)
        _pub0 = self.public_url_var.get().strip().rstrip("/")
        self.callback_var = tk.StringVar(value=f"{_pub0}/oauth/callback" if _pub0 else "")
        def _on_public_url_changed(*_w: object) -> None:
            self.callback_var.set(
                f"{self.public_url_var.get().strip().rstrip('/')}/oauth/callback"
                if self.public_url_var.get().strip()
                else ""
            )
            if getattr(self, "_suppress_pub_url_persist", False):
                return
            self._save_guardian_ui_settings()

        self.public_url_var.trace_add("write", _on_public_url_changed)
        cb_entry = ttk.Entry(oauth_row4, textvariable=self.callback_var, width=58, state="readonly")
        cb_entry.pack(side=tk.LEFT, padx=6)
        def _copy_callback() -> None:
            self.clipboard_clear()
            self.clipboard_append(self.callback_var.get())
            self.status_var.set(t("copy_callback_url"))

        ttk.Button(oauth_row4, text="Kopieren", command=_copy_callback).pack(side=tk.LEFT, padx=4)
        ttk.Button(oauth_row4, text="OAuth (GitHub) testen", command=self._oauth_connectivity_test).pack(side=tk.LEFT, padx=8)

        audit_conn = ttk.Frame(oauth_frame)
        audit_conn.pack(fill=tk.X, pady=(8, 0))
        self._conn_audit_log_link = tk.Label(
            audit_conn,
            text="Access-Log (Audit) öffnen — heutige JSONL",
            fg="#1a5f9e",
            cursor="hand2",
            font=("Segoe UI", 9, "underline"),
        )
        self._conn_audit_log_link.pack(side=tk.LEFT)
        self._conn_audit_log_link.bind("<Button-1>", lambda _e: self._open_today_access_log())

        # --- Tunnel Info ---
        tunnel_frame = ttk.LabelFrame(container, text="Cloudflare Tunnel (Windows-Dienst)", padding=8)
        tunnel_frame.pack(fill=tk.X, expand=False, pady=6)
        ttk.Label(
            tunnel_frame,
            text="Optional: Cloudflare Tunnel oder anderen Dienst lokal betreiben — nicht Teil von MCC Lite.",
        ).pack(anchor=tk.W)
        ttk.Label(tunnel_frame, text=t("tunnel_default_hint")).pack(anchor=tk.W)
        svc_row = ttk.Frame(tunnel_frame)
        svc_row.pack(fill=tk.X, pady=4)
        self.svc_status_var = tk.StringVar(value="Dienststatus: wird geprüft...")
        ttk.Label(svc_row, textvariable=self.svc_status_var).pack(side=tk.LEFT)
        ttk.Button(svc_row, text="Status prüfen", command=self._check_tunnel_service).pack(side=tk.LEFT, padx=8)

        # --- ChatGPT Connector Info ---
        chatgpt_frame = ttk.LabelFrame(container, text="ChatGPT Connector (Schnellreferenz)", padding=8)
        chatgpt_frame.pack(fill=tk.X, expand=False, pady=6)
        _ph = "http://127.0.0.1:8766/mcp (oder Ihre Public Base URL + /mcp)"
        info_lines = [
            ("MCP-Server URL:", _ph, False),
            ("Authentifizierung:", "OAuth (automatische DCR)", False),
            ("Server-Status:", "siehe Betrieb-Tab →", True),
        ]
        for label_text, value_text, is_link in info_lines:
            row = ttk.Frame(chatgpt_frame)
            row.pack(fill=tk.X, pady=1)
            ttk.Label(row, text=label_text, width=22, anchor=tk.W).pack(side=tk.LEFT)
            if is_link:
                link_lbl = tk.Label(row, text=value_text, fg="#1a5f9e", cursor="hand2", font=("Segoe UI", 9, "underline"))
                link_lbl.pack(side=tk.LEFT)
                link_lbl.bind("<Button-1>", lambda _e: self._switch_section("Betrieb"))
            else:
                ttk.Label(row, text=value_text, foreground="#2a7").pack(side=tk.LEFT)

        bearer_frame = ttk.LabelFrame(container, text="Bearer Keys (Keystore)", padding=8)
        bearer_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        ttk.Label(
            bearer_frame,
            text="Keys werden verschlüsselt gespeichert. Nach Generierung in den Connector eintragen. "
            "Server neu starten, damit ein neuer Key wirkt.",
            wraplength=900,
        ).pack(anchor=tk.W)
        bcanvas = tk.Canvas(bearer_frame, borderwidth=0, highlightthickness=0, height=120)
        bscroll = ttk.Scrollbar(bearer_frame, orient="vertical", command=bcanvas.yview)
        binner = ttk.Frame(bcanvas)
        bid = bcanvas.create_window((0, 0), window=binner, anchor="nw")

        def _bconf(_e: object) -> None:
            bcanvas.configure(scrollregion=bcanvas.bbox("all"))

        def _bwidth(e: tk.Event) -> None:
            bcanvas.itemconfig(bid, width=e.width)

        binner.bind("<Configure>", _bconf)
        bcanvas.bind("<Configure>", _bwidth)
        bcanvas.configure(yscrollcommand=bscroll.set)
        bcanvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=6)
        bscroll.pack(side=tk.RIGHT, fill=tk.Y, pady=6)

        bf = ttk.Frame(binner)
        bf.pack(fill=tk.X)
        ttk.Button(bf, text="Key generieren (codex)", command=lambda: self._generate_bearer_key("codex")).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="Key generieren (gpt)", command=lambda: self._generate_bearer_key("gpt")).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="Keystore zurücksetzen …", command=self._factory_reset_keystore).pack(side=tk.LEFT, padx=20)

    def _build_blocklist_tab(self, tab: ttk.Frame) -> None:
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            frame,
            text="Blocklisten — Policy (Layer 1) und IP-Sperren",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor=tk.W)

        pol_blocked = ttk.LabelFrame(frame, text="Policy-Verbotslisten (mcp_policy.json → blocked)", padding=8)
        pol_blocked.pack(fill=tk.BOTH, expand=True, pady=(4, 8))
        self.dir_names_txt = self._textarea(pol_blocked, "Gesperrte Ordnernamen", 3)
        self.path_parts_txt = self._textarea(pol_blocked, "Gesperrte Pfadteile", 3)
        self.suffixes_txt = self._textarea(pol_blocked, "Gesperrte Endungen", 3)
        self.file_names_txt = self._textarea(pol_blocked, "Gesperrte Dateinamen", 3)
        self.name_contains_txt = self._textarea(pol_blocked, "Gesperrte Namens-Tokens", 3)
        ttk.Label(
            pol_blocked,
            text="Änderungen mit „Policy speichern“ (Policy-Tab oder Strg+S) schreiben.",
            foreground="#555",
        ).pack(anchor=tk.W, pady=(4, 0))

        ttk.Label(frame, text="IP-Blockliste (config/blocked_ips.json)", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W)

        struct = ttk.LabelFrame(frame, text="Einträge", padding=6)
        struct.pack(fill=tk.BOTH, expand=True, pady=(6, 4))
        cols = ("ip", "reason", "since", "auto")
        titles = {"ip": "IP / Schlüssel", "reason": "Grund", "since": "Gesperrt (UTC)", "auto": "Auto"}
        twrap = ttk.Frame(struct)
        twrap.pack(fill=tk.BOTH, expand=True)
        sb_tr = ttk.Scrollbar(twrap, orient="vertical")
        sb_tr.pack(side=tk.RIGHT, fill=tk.Y)
        self.blocklist_tree = ttk.Treeview(twrap, columns=cols, show="headings", yscrollcommand=sb_tr.set, height=8)
        for c, w in (("ip", 160), ("reason", 220), ("since", 200), ("auto", 60)):
            self.blocklist_tree.heading(c, text=titles[c])
            self.blocklist_tree.column(c, width=w, anchor=tk.W, stretch=(c == "reason"))
        self.blocklist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_tr.config(command=self.blocklist_tree.yview)

        bbar = ttk.Frame(struct)
        bbar.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(bbar, text="IP hinzufügen …", command=self._blocklist_add_ip_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(bbar, text="Auswahl entfernen", command=self._blocklist_remove_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(bbar, text="Speichern", command=self._blocklist_save_from_tree).pack(side=tk.LEFT, padx=8)

        self._block_ip_json_expanded = tk.BooleanVar(value=False)

        def _toggle_ip_json() -> None:
            if self._block_ip_json_expanded.get():
                bl_json_frame.pack(fill=tk.BOTH, expand=False, pady=(4, 0))
            else:
                bl_json_frame.pack_forget()

        ttk.Checkbutton(
            frame,
            text="Erweitert: IP-Blockliste als JSON bearbeiten",
            variable=self._block_ip_json_expanded,
            command=_toggle_ip_json,
        ).pack(anchor=tk.W, pady=(2, 0))

        bl_json_frame = ttk.LabelFrame(frame, text="JSON (blocked_ips.json)", padding=4)
        bl_wrap = ttk.Frame(bl_json_frame)
        bl_wrap.pack(fill=tk.BOTH, expand=True)
        sb_bl = ttk.Scrollbar(bl_wrap, orient="vertical")
        sb_bl.pack(side=tk.RIGHT, fill=tk.Y)
        self.blocklist_text = tk.Text(bl_wrap, height=8, wrap=tk.WORD, yscrollcommand=sb_bl.set)
        self.blocklist_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_bl.config(command=self.blocklist_text.yview)

        bf = ttk.Frame(frame)
        bf.pack(fill=tk.X, pady=6)
        ttk.Button(bf, text="Aktualisieren", command=self._refresh_blocklist_view).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="JSON → Tabelle", command=self._blocklist_sync_json_to_tree).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="Datei öffnen", command=self._open_blocked_ips_file).pack(side=tk.LEFT, padx=4)
        self._refresh_blocklist_view()

    def _refresh_blocklist_view(self) -> None:
        if not hasattr(self, "blocklist_text"):
            return
        self.blocklist_text.delete("1.0", tk.END)
        if BLOCKED_IPS_FILE.exists():
            try:
                raw = BLOCKED_IPS_FILE.read_text(encoding="utf-8")
                self.blocklist_text.insert("1.0", raw)
            except Exception as exc:
                self.blocklist_text.insert("1.0", str(exc))
        else:
            self.blocklist_text.insert("1.0", "{}\n")
        self._blocklist_fill_tree_from_file()

    def _blocklist_fill_tree_from_file(self) -> None:
        if not hasattr(self, "blocklist_tree"):
            return
        for iid in self.blocklist_tree.get_children():
            self.blocklist_tree.delete(iid)
        data: dict[str, Any] = {}
        if BLOCKED_IPS_FILE.exists():
            try:
                loaded = json.loads(BLOCKED_IPS_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
            except Exception:
                pass
        for ip, meta in sorted(data.items(), key=lambda x: str(x[0])):
            if not isinstance(meta, dict):
                meta = {}
            self.blocklist_tree.insert(
                "",
                tk.END,
                values=(
                    str(ip),
                    str(meta.get("reason", "")),
                    str(meta.get("blocked_at", "")),
                    "ja" if meta.get("auto") else "nein",
                ),
            )

    def _blocklist_sync_json_to_tree(self) -> None:
        raw = self.blocklist_text.get("1.0", tk.END).strip()
        try:
            loaded = json.loads(raw) if raw else {}
            if not isinstance(loaded, dict):
                raise ValueError("Top-Level muss ein Objekt sein")
        except Exception as exc:
            messagebox.showerror("Blocklist", f"JSON ungültig:\n{exc}", parent=self)
            return
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        BLOCKED_IPS_FILE.write_text(json.dumps(loaded, indent=2, ensure_ascii=False), encoding="utf-8")
        self._refresh_blocklist_view()
        self.status_var.set("Status: Blocklist aus JSON übernommen")

    def _blocklist_save_from_tree(self) -> None:
        data: dict[str, Any] = {}
        for iid in self.blocklist_tree.get_children():
            row = self.blocklist_tree.item(iid, "values")
            if not row or not str(row[0]).strip():
                continue
            ip = str(row[0]).strip()
            data[ip] = {
                "reason": str(row[1]).strip() or "manual_ui",
                "blocked_at": str(row[2]).strip() or datetime.now(timezone.utc).isoformat(),
                "auto": str(row[3]).strip().lower() in ("ja", "yes", "true", "1"),
            }
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        BLOCKED_IPS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        self._refresh_blocklist_view()
        self.status_var.set("Status: Blocklist gespeichert")

    def _blocklist_add_ip_dialog(self) -> None:
        ip = simpledialog.askstring("IP sperren", "IP-Adresse oder Schlüssel:", parent=self)
        if not ip or not str(ip).strip():
            return
        ip = str(ip).strip()
        self.blocklist_tree.insert(
            "",
            tk.END,
            values=(ip, "manual_ui", datetime.now(timezone.utc).isoformat(), "nein"),
        )

    def _blocklist_remove_selected(self) -> None:
        sel = self.blocklist_tree.selection()
        if not sel:
            return
        for iid in sel:
            self.blocklist_tree.delete(iid)

    def _open_blocked_ips_file(self) -> None:
        try:
            os.startfile(BLOCKED_IPS_FILE)  # type: ignore[attr-defined]
        except Exception:
            messagebox.showinfo("Blocklist", str(BLOCKED_IPS_FILE))

    def _generate_bearer_key(self, client: str) -> None:
        if self._keystore_store is None:
            return
        pw = self._require_master_password()
        if not pw:
            return
        new_key = f"mcc-{client}-" + secrets.token_urlsafe(42)
        self._keystore_store[client] = new_key
        save_keystore(pw, self._keystore_store)
        self.clipboard_clear()
        self.clipboard_append(new_key)
        running = self.server_proc is not None and self.server_proc.poll() is None
        if running:
            if messagebox.askyesno(
                "Server neu starten?",
                f"Neuer Key für '{client}' wurde erzeugt und in die Zwischenablage kopiert.\n\n"
                "Der Server muss neu gestartet werden, damit der Key aktiv wird und der alte ungültig ist.\n\n"
                "Jetzt neu starten?",
            ):
                self.stop_server()
                self.start_server()
        else:
            messagebox.showinfo("Key", f"Key für '{client}' gespeichert. Wird beim nächsten Server-Start aktiv.")

    def _hydrate_oauth_from_keystore(self) -> None:
        if not self._keystore_store:
            return
        cid = self._keystore_store.get(KEYSTORE_OAUTH_CLIENT_ID, "").strip()
        csec = self._keystore_store.get(KEYSTORE_OAUTH_CLIENT_SECRET, "").strip()
        if cid:
            self.client_id_var.set(cid)
        if csec:
            self.client_secret_var.set(csec)

    def _save_oauth_to_keystore(self) -> None:
        if self._keystore_store is None:
            messagebox.showerror("Keystore", "Keystore nicht entsperrt.")
            return
        pw = self._require_master_password()
        if not pw:
            return
        self._keystore_store[KEYSTORE_OAUTH_CLIENT_ID] = self.client_id_var.get().strip()
        self._keystore_store[KEYSTORE_OAUTH_CLIENT_SECRET] = self.client_secret_var.get().strip()
        try:
            save_keystore(pw, self._keystore_store)
        except OSError as exc:
            messagebox.showerror("Keystore", f"Speichern fehlgeschlagen:\n{exc}")
            return
        self._oauth_secret_rotated_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._save_guardian_ui_settings()
        self._sync_oauth_rotation_label()
        self.status_var.set("Status: OAuth-Daten im Keystore gespeichert")
        messagebox.showinfo("Keystore", "Client ID und Secret wurden verschlüsselt gespeichert.")
        # Secrets nur beim Start (MCP_SECRETS_FILE) — ohne Neustart wirkt ein neues Secret nicht
        # nutzt der laufende Server weiter das alte Secret (häufiger Grund für „Update wirkt nicht“).
        running = self.server_proc is not None and self.server_proc.poll() is None
        if running:
            if messagebox.askyesno(
                "Server neu starten?",
                "OAuth-Daten sind in keystore.enc gespeichert.\n\n"
                "Der MCP-Server hat die alten Werte aber noch im Speicher — er liest den Keystore "
                "nicht zur Laufzeit nach.\n\n"
                "Jetzt Server stoppen und neu starten, damit Client ID / Secret aktiv werden?",
            ):
                self.stop_server()
                self.start_server()

    def _factory_reset_keystore(self) -> None:
        confirm = simpledialog.askstring(
            "Keystore zurücksetzen",
            "Alle Keys und das Master-Passwort löschen.\nZur Bestätigung RESET eingeben:",
            parent=self,
        )
        if confirm != "RESET":
            return
        for p in (KEYSTORE_PATH, SALT_PATH):
            if p.exists():
                p.unlink()
        self._keystore_store = {}
        self._master_password = ""
        messagebox.showinfo("Reset", "Keystore gelöscht. App bitte neu starten.")
        self.destroy()

    def _build_ops_tab(self, tab: ttk.Frame) -> None:
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Betrieb / Build", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W)

        hf = ttk.LabelFrame(frame, text="Health-Check (Periodisch)", padding=6)
        hf.pack(fill=tk.X, pady=4)
        ttk.Checkbutton(hf, text="Aktiv", variable=self._health_enabled).pack(side=tk.LEFT, padx=4)
        ttk.Label(hf, text="Intervall (Min):").pack(side=tk.LEFT)
        ttk.Spinbox(hf, from_=1, to=120, width=5, textvariable=self._health_interval_min).pack(side=tk.LEFT, padx=4)
        ttk.Button(hf, text="Health-Log anzeigen", command=lambda: self._open_text_file(HEALTH_LOG_FILE)).pack(side=tk.LEFT, padx=8)
        ttk.Label(
            hf,
            text="(Kurzprotokoll je Lauf auch im Betriebslog unten)",
            foreground="#555",
        ).pack(side=tk.LEFT, padx=6)

        tf = ttk.LabelFrame(frame, text="Auto-Timeout (Inaktivität)", padding=6)
        tf.pack(fill=tk.X, pady=4)
        ttk.Checkbutton(tf, text="Aktiv", variable=self._timeout_enabled).pack(side=tk.LEFT, padx=4)
        ttk.Label(tf, text="Nach (Min) ohne Log-Event:").pack(side=tk.LEFT)
        ttk.Spinbox(tf, from_=5, to=24 * 60, width=5, textvariable=self._timeout_minutes).pack(side=tk.LEFT, padx=4)

        ttk.Button(frame, text="Nur MCP Server starten", command=self.start_server).pack(anchor=tk.W, pady=3)
        ttk.Button(frame, text="Nur Tunnel starten", command=self.start_tunnel).pack(anchor=tk.W, pady=3)
        ttk.Button(frame, text="Nur Tunnel stoppen", command=self.stop_tunnel).pack(anchor=tk.W, pady=3)
        ttk.Button(frame, text="Nur Server stoppen", command=self.stop_server).pack(anchor=tk.W, pady=3)
        # Nur bei Entwicklung (python …): vermeidet „EXE baut EXE“-Verwirrung in der Verteilungs-EXE.
        if not getattr(sys, "frozen", False):
            ttk.Button(
                frame,
                text="EXE Build ausführen (PyInstaller)",
                command=self.build_exe,
            ).pack(anchor=tk.W, pady=8)

        ttk.Label(frame, text="Hinweis: Beim Schließen oder Trennen wird immer automatisch ein JSON-Export erzeugt.").pack(anchor=tk.W, pady=10)

        log_outer = ttk.LabelFrame(frame, text="Betriebslog (Sitzung)", padding=6)
        log_outer.pack(fill=tk.BOTH, expand=True)
        log_bar = ttk.Frame(log_outer)
        log_bar.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(
            log_bar,
            text="„Anzeige leeren“ betrifft nur dieses Textfeld – nicht guardian_health.jsonl oder andere Dateien.",
            foreground="#555",
        ).pack(side=tk.LEFT, anchor=tk.W)
        ttk.Button(log_bar, text="Anzeige leeren", command=self._clear_ops_log_ui_only).pack(side=tk.RIGHT)

        olf = ttk.Frame(log_outer)
        olf.pack(fill=tk.BOTH, expand=True)
        sb_ops = ttk.Scrollbar(olf)
        sb_ops.pack(side=tk.RIGHT, fill=tk.Y)
        self.ops_log = tk.Text(olf, height=16, yscrollcommand=sb_ops.set)
        self.ops_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_ops.config(command=self.ops_log.yview)


    def _build_advanced_tab(self, tab: ttk.Frame) -> None:
        canvas = tk.Canvas(tab, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        container = ttk.Frame(canvas, padding=10)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)
        cid = canvas.create_window((0, 0), window=container, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cid, width=e.width))
        container.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        ttk.Label(container, text="Erweiterte Sicherheitseinstellungen", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        ttk.Label(container, text="Jede Einstellung zeigt eine Risiko-Einstufung. Empfohlene Werte sind voreingestellt.", foreground="#555", wraplength=900).pack(anchor=tk.W, pady=(0, 12))

        def risk_label(parent):
            lbl = tk.Label(parent, text="SICHER", bg="#2e7d32", fg="white", font=("Consolas", 9, "bold"), padx=6, pady=1)
            lbl.pack(side=tk.LEFT, padx=8)
            return lbl

        def setting_row(parent, label_text, widget_factory, risk_lbl, desc):
            f = ttk.LabelFrame(parent, text=label_text, padding=6)
            f.pack(fill=tk.X, pady=4)
            row = ttk.Frame(f)
            row.pack(fill=tk.X)
            w = widget_factory(row)
            w.pack(side=tk.LEFT)
            rl = risk_label(row)
            risk_lbl.append(rl)
            ttk.Label(f, text=desc, foreground="#666", wraplength=850).pack(anchor=tk.W, pady=(4, 0))
            return rl

        self._risk_labels = []

        rl_write = setting_row(container, "Max. Schreibgröße (Bytes)",
            lambda p: ttk.Spinbox(p, from_=0, to=100_000_000, width=14, textvariable=self._adv_max_write),
            self._risk_labels,
            "Begrenzt wie viel Daten ein KI-Client in einem einzelnen Schreibvorgang speichern darf. "
            "Schützt vor versehentlichem oder böswilligem Füllen der Festplatte. 0 = unbegrenzt.")

        rl_search = setting_row(container, "Suche: Aktives Projekt zuerst",
            lambda p: ttk.Checkbutton(p, text="Aktiv", variable=self._adv_search_prio),
            self._risk_labels,
            "Durchsucht zuerst die Ordner, in denen du aktiv arbeitest (write_allow_paths). "
            "Verhindert, dass alte Backups die Ergebnisse verdrängen.")

        rl_rate = setting_row(container, "Max. Anfragen pro Minute",
            lambda p: ttk.Spinbox(p, from_=1, to=1000, width=8, textvariable=self._adv_rate_limit_var),
            self._risk_labels,
            "Schreibt in die Policy unter rate_limit.requests_per_minute (1–1000), wenn du unten "
            "„Einstellungen speichern“ klickst. block_after_failures bleibt unverändert. "
            "Laufenden MCP-Server nach Änderung neu starten.")

        rl_norm = setting_row(container, "Windows-Pfad-Normalisierung",
            lambda p: ttk.Checkbutton(p, text="Aktiv", variable=self._adv_path_norm),
            self._risk_labels,
            "Erkennt und blockiert Tricks wie verkürzte Dateinamen (8.3), versteckte Datenströme (ADS) "
            "und Netzwerkpfade (UNC). Nur deaktivieren, wenn spezielle Pfadformate benötigt werden.")

        rl_del = setting_row(container, "Kindpfad-Prüfung beim Löschen",
            lambda p: ttk.Checkbutton(p, text="Aktiv", variable=self._adv_delete_check),
            self._risk_labels,
            "Prüft vor dem Löschen eines Ordners, ob darin geschützte Dateien liegen (.env, Schlüssel etc.). "
            "Verhindert versehentliches Löschen sensibler Daten.")

        rl_lock = setting_row(container, "Automatische GUI-Sperre",
            lambda p: (
                ttk.Checkbutton(p, text="Aktiv", variable=self._adv_auto_lock),
                ttk.Label(p, text="  Nach (Min):"),
                ttk.Spinbox(p, from_=1, to=120, width=5, textvariable=self._adv_auto_lock_min),
            )[-1],
            self._risk_labels,
            "Sperrt die Guardian-Oberfläche nach Inaktivität. Schützt davor, dass jemand im Vorbeigehen "
            "Einstellungen oder Schlüssel sieht. Erfordert KEINE erneute Passworteingabe.")

        rl_log = setting_row(container, "Alte Logs automatisch löschen",
            lambda p: (
                ttk.Checkbutton(p, text="Aktiv", variable=self._adv_log_retention),
                ttk.Label(p, text="  Nach (Tagen):"),
                ttk.Spinbox(p, from_=1, to=3650, width=6, textvariable=self._adv_log_retention_days),
            )[-1],
            self._risk_labels,
            "Löscht Access-Log-Dateien die älter als die eingestellte Anzahl Tage sind. "
            "Standard: aus – alle Logs werden unbegrenzt aufbewahrt, damit jeder Zugriff nachvollziehbar bleibt.")

        rl_geo = setting_row(container, "Standort-Tracking (Cloudflare Geo)",
            lambda p: ttk.Checkbutton(p, text="Aktiv", variable=self._adv_geo_tracking),
            self._risk_labels,
            "Zeichnet das Herkunftsland eingehender Anfragen auf, sofern die Verbindung über Cloudflare läuft. "
            "Keine externen Abfragen – die Information kommt direkt aus dem Cloudflare-Header.")

        pi_f = ttk.LabelFrame(container, text="Policy-Integrität (SHA256)", padding=6)
        pi_f.pack(fill=tk.X, pady=4)
        row_pi = ttk.Frame(pi_f)
        row_pi.pack(fill=tk.X)

        def _pi_toggle() -> None:
            if self._suppress_pi_ui_events:
                return
            if not self._pi_enabled.get():
                if not messagebox.askyesno(
                    "Policy-Integrität",
                    "Die Integritätsprüfung schützt vor unbemerkten Policy-Änderungen.\n\nWirklich deaktivieren?",
                    parent=self,
                ):
                    self._suppress_pi_ui_events = True
                    self._pi_enabled.set(True)
                    self._suppress_pi_ui_events = False

        ttk.Checkbutton(row_pi, text="Aktiv", variable=self._pi_enabled, command=_pi_toggle).pack(side=tk.LEFT)
        rl_pi = risk_label(row_pi)
        self._risk_labels.append(rl_pi)
        row_scope_a = ttk.Frame(pi_f)
        row_scope_a.pack(fill=tk.X, pady=(6, 0))
        ttk.Radiobutton(
            row_scope_a,
            text="Alle MCP-Tools (SHA bei jedem passenden Request)",
            variable=self._pi_scope,
            value="all",
        ).pack(anchor=tk.W)
        row_scope_ai = ttk.Frame(pi_f)
        row_scope_ai.pack(fill=tk.X, pady=(2, 0))
        ttk.Radiobutton(
            row_scope_ai,
            text="Alle MCP-Tools, SHA-Prüfung nur alle",
            variable=self._pi_scope,
            value="all_interval",
        ).pack(side=tk.LEFT)
        ttk.Spinbox(
            row_scope_ai, from_=1, to=10080, width=6, textvariable=self._pi_interval_min
        ).pack(side=tk.LEFT, padx=6)
        ttk.Label(row_scope_ai, text="Minuten").pack(side=tk.LEFT)
        row_scope_s = ttk.Frame(pi_f)
        row_scope_s.pack(fill=tk.X, pady=(4, 0))
        ttk.Radiobutton(
            row_scope_s, text="Nur ausgewählte Kategorien", variable=self._pi_scope, value="selective"
        ).pack(anchor=tk.W)
        row_cat = ttk.Frame(pi_f)
        row_cat.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(row_cat, text="Kategorien (bei „Nur ausgewählte“):").pack(side=tk.LEFT)
        ttk.Checkbutton(row_cat, text="Schreiben", variable=self._pi_cat_write).pack(side=tk.LEFT, padx=(10, 4))
        ttk.Checkbutton(row_cat, text="Lesen", variable=self._pi_cat_read).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row_cat, text="Schreib-/Ausführungstools", variable=self._pi_cat_exec).pack(side=tk.LEFT, padx=4)
        row_ks = ttk.Frame(pi_f)
        row_ks.pack(fill=tk.X, pady=(6, 0))
        ttk.Checkbutton(
            row_ks,
            text="Zusätzlich keystore.enc + keystore.salt (SHA256 der Dateien, Inhalt bleibt verschlüsselt)",
            variable=self._pi_include_keystore,
        ).pack(anchor=tk.W)
        ttk.Label(
            pi_f,
            text="Speichert beim ersten geschützten Request einen SHA256-Referenzwert der Policy-Datei. "
                 "Weicht die Datei danach ab (z. B. externe Bearbeitung), werden betroffene Zugriffe abgelehnt. "
                 "„Nur alle X Minuten“ prüft alle Tools wie „Alle“, begrenzt aber die SHA-Vergleiche (zwischen den "
                 "Prüfungen kann eine Policy-Änderung kurz unentdeckt bleiben). "
                 "Keystore: Es werden nur die verschlüsselten Dateien gehasht — erkennt Austausch/Manipulation ohne Klartext. "
                 "Nach Änderung an Policy, Keystore oder Salt den MCP-Server neu starten, damit die Referenz passt.",
            foreground="#666",
            wraplength=850,
        ).pack(anchor=tk.W, pady=(6, 0))

        info_f = ttk.LabelFrame(container, text="Kontrollfluss-Sicherung (deny+return)", padding=6)
        info_f.pack(fill=tk.X, pady=4)
        info_r = ttk.Frame(info_f)
        info_r.pack(fill=tk.X)
        cb = ttk.Checkbutton(info_r, text="Immer aktiv", state="disabled")
        cb.state(["selected", "disabled"])
        cb.pack(side=tk.LEFT)
        tk.Label(info_r, text="SICHER", bg="#2e7d32", fg="white", font=("Consolas", 9, "bold"), padx=6, pady=1).pack(side=tk.LEFT, padx=8)
        ttk.Label(info_f, text="Interne Sicherung: Der Server bricht bei einer Zugriffsverletzung sofort ab, "
                  "statt weiterzulaufen. Kann nicht deaktiviert werden.", foreground="#666", wraplength=850).pack(anchor=tk.W, pady=(4, 0))

        btn_f = ttk.Frame(container)
        btn_f.pack(fill=tk.X, pady=10)
        ttk.Button(btn_f, text="Einstellungen laden", command=self._load_advanced_from_policy).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_f, text="Einstellungen speichern", command=self._save_advanced_to_policy).pack(side=tk.LEFT, padx=4)

        self._update_all_risk_tags()
        for var in (
            self._adv_max_write,
            self._adv_search_prio,
            self._adv_path_norm,
            self._adv_delete_check,
            self._adv_auto_lock,
            self._adv_log_retention,
            self._adv_geo_tracking,
            self._pi_enabled,
            self._pi_scope,
            self._pi_cat_write,
            self._pi_cat_read,
            self._pi_cat_exec,
            self._pi_interval_min,
            self._pi_include_keystore,
        ):
            var.trace_add("write", lambda *_: self._update_all_risk_tags())

    def _update_all_risk_tags(self) -> None:
        if not hasattr(self, "_risk_labels") or len(self._risk_labels) < 9:
            return
        mw = self._adv_max_write.get()
        self._set_risk(self._risk_labels[0], "SICHER" if 0 < mw <= 5_000_000 else ("WARNUNG" if mw <= 20_000_000 else "KRITISCH"))
        self._set_risk(self._risk_labels[1], "SICHER" if self._adv_search_prio.get() else "WARNUNG")
        self._set_risk(self._risk_labels[2], "SICHER")
        self._set_risk(self._risk_labels[3], "SICHER" if self._adv_path_norm.get() else "KRITISCH")
        self._set_risk(self._risk_labels[4], "SICHER" if self._adv_delete_check.get() else "KRITISCH")
        self._set_risk(self._risk_labels[5], "SICHER" if self._adv_auto_lock.get() else "INFO")
        self._set_risk(self._risk_labels[6], "SICHER" if not self._adv_log_retention.get() else "WARNUNG")
        self._set_risk(self._risk_labels[7], "INFO" if not self._adv_geo_tracking.get() else "SICHER")
        if not self._pi_enabled.get():
            self._set_risk(self._risk_labels[8], "WARNUNG")
        elif self._pi_scope.get() == "selective" and not (
            self._pi_cat_write.get() or self._pi_cat_read.get() or self._pi_cat_exec.get()
        ):
            self._set_risk(self._risk_labels[8], "KRITISCH")
        elif self._pi_scope.get() == "all_interval" and int(self._pi_interval_min.get() or 0) < 1:
            self._set_risk(self._risk_labels[8], "KRITISCH")
        elif self._pi_enabled.get() and not self._pi_include_keystore.get():
            self._set_risk(self._risk_labels[8], "WARNUNG")
        else:
            self._set_risk(self._risk_labels[8], "SICHER")

    @staticmethod
    def _set_risk(label: tk.Label, level: str) -> None:
        colors = {
            "SICHER": ("#2e7d32", "white"),
            "WARNUNG": ("#e6a800", "black"),
            "KRITISCH": ("#c62828", "white"),
            "INFO": ("#555555", "white"),
        }
        bg, fg = colors.get(level, ("#555555", "white"))
        label.config(text=level, bg=bg, fg=fg)

    def _load_advanced_from_policy(self) -> None:
        self._suppress_pi_ui_events = True
        try:
            pol = self._read_policy_file()
            adv = pol.get("advanced", {})
            if not isinstance(adv, dict):
                adv = {}
            self._adv_max_write.set(int(adv.get("max_write_bytes", 5000000)))
            self._adv_search_prio.set(bool(adv.get("search_prioritize_write_paths", True)))
            self._adv_path_norm.set(bool(adv.get("path_normalization_enabled", True)))
            self._adv_delete_check.set(bool(adv.get("recursive_delete_check_children", True)))
            self._adv_auto_lock.set(bool(adv.get("gui_auto_lock_enabled", False)))
            self._adv_auto_lock_min.set(int(adv.get("gui_auto_lock_minutes", 15)))
            self._adv_log_retention.set(bool(adv.get("log_retention_enabled", False)))
            self._adv_log_retention_days.set(int(adv.get("log_retention_days", 90)))
            self._adv_geo_tracking.set(bool(adv.get("geo_tracking_enabled", False)))
            rl = pol.get("rate_limit") if isinstance(pol.get("rate_limit"), dict) else {}
            self._adv_rate_limit_var.set(int(rl.get("requests_per_minute", 60)))
            pi = adv.get("policy_integrity", {})
            if isinstance(pi, dict):
                self._pi_enabled.set(bool(pi.get("enabled", True)))
                sc = str(pi.get("scope", "selective"))
                self._pi_scope.set(sc if sc in ("all", "selective", "all_interval") else "selective")
                try:
                    self._pi_interval_min.set(max(1, int(pi.get("interval_minutes", 5))))
                except (TypeError, ValueError):
                    self._pi_interval_min.set(5)
                cats = pi.get("categories") if isinstance(pi.get("categories"), list) else ["write", "exec"]
                cats_l = {str(c).lower() for c in cats}
                self._pi_cat_write.set("write" in cats_l)
                self._pi_cat_read.set("read" in cats_l)
                self._pi_cat_exec.set("exec" in cats_l)
                self._pi_include_keystore.set(bool(pi.get("include_keystore_files", True)))
            else:
                self._pi_enabled.set(True)
                self._pi_scope.set("selective")
                self._pi_interval_min.set(5)
                self._pi_include_keystore.set(True)
                self._pi_cat_write.set(True)
                self._pi_cat_read.set(False)
                self._pi_cat_exec.set(True)
        finally:
            self._suppress_pi_ui_events = False
        self.status_var.set("Status: Erweiterte Einstellungen geladen")

    def _save_advanced_to_policy(self) -> None:
        pol = self._read_policy_file()
        if self._pi_scope.get() == "selective" and not (
            self._pi_cat_write.get() or self._pi_cat_read.get() or self._pi_cat_exec.get()
        ):
            messagebox.showwarning(
                "Policy-Integrität",
                "Bei „Nur ausgewählte Kategorien“ muss mindestens eine Kategorie "
                "(Schreiben, Lesen oder Ausführung) aktiviert sein.",
            )
            return
        if self._pi_scope.get() == "all_interval" and int(self._pi_interval_min.get() or 0) < 1:
            messagebox.showwarning(
                "Policy-Integrität",
                "Bei „Alle … nur alle X Minuten“ muss das Intervall mindestens 1 Minute betragen.",
            )
            return
        pi_cats: list[str] = []
        if self._pi_cat_write.get():
            pi_cats.append("write")
        if self._pi_cat_read.get():
            pi_cats.append("read")
        if self._pi_cat_exec.get():
            pi_cats.append("exec")
        pol["advanced"] = {
            "max_write_bytes": self._adv_max_write.get(),
            "search_prioritize_write_paths": self._adv_search_prio.get(),
            "path_normalization_enabled": self._adv_path_norm.get(),
            "recursive_delete_check_children": self._adv_delete_check.get(),
            "gui_auto_lock_enabled": self._adv_auto_lock.get(),
            "gui_auto_lock_minutes": self._adv_auto_lock_min.get(),
            "log_retention_enabled": self._adv_log_retention.get(),
            "log_retention_days": self._adv_log_retention_days.get(),
            "geo_tracking_enabled": self._adv_geo_tracking.get(),
            "policy_integrity": {
                "enabled": self._pi_enabled.get(),
                "scope": self._pi_scope.get(),
                "categories": pi_cats,
                "interval_minutes": max(1, int(self._pi_interval_min.get() or 5)),
                "include_keystore_files": self._pi_include_keystore.get(),
            },
        }
        pol.pop("python_automation", None)
        try:
            rpm = int(self._adv_rate_limit_var.get())
        except (TypeError, ValueError):
            rpm = 60
        rpm = max(1, min(1000, rpm))
        old_rl = pol.get("rate_limit") if isinstance(pol.get("rate_limit"), dict) else {}
        try:
            baf = int(old_rl.get("block_after_failures", 5))
        except (TypeError, ValueError):
            baf = 5
        baf = max(1, min(1000, baf))
        pol["rate_limit"] = {"requests_per_minute": rpm, "block_after_failures": baf}
        POLICY_FILE.write_text(json.dumps(pol, ensure_ascii=False, indent=2), encoding="utf-8")
        self.status_var.set("Status: Erweiterte Einstellungen gespeichert")
        self._ops("Erweiterte Einstellungen gespeichert (inkl. rate_limit)")

    def _open_text_file(self, path: Path) -> None:
        try:
            os.startfile(path)  # type: ignore[attr-defined]
        except Exception:
            messagebox.showinfo("Datei", str(path))

    def _build_help_tab(self, tab: ttk.Frame) -> None:
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Hilfe aktualisieren", command=self._refresh_help_text).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Hilfe als Datei speichern", command=self._save_help_file).pack(side=tk.LEFT, padx=6)

        hf = ttk.Frame(frame)
        hf.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        sb = ttk.Scrollbar(hf)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.help_text = tk.Text(hf, wrap=tk.WORD, yscrollcommand=sb.set)
        self.help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=self.help_text.yview)
        self._refresh_help_text()

    def _current_mcp_url(self) -> str:
        url = self._parse_tunnel_url()
        if url:
            return f"{url}/mcp"
        port = self.port_var.get().strip() or "8766"
        return f"http://127.0.0.1:{port}/mcp"

    def _check_tunnel_service(self) -> None:
        """Prüfe ob der cloudflared Windows-Dienst läuft."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-Service cloudflared -ErrorAction SilentlyContinue).Status"],
                capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()
            if status == "Running":
                self.svc_status_var.set("Dienststatus: ✓ Läuft")
            elif status:
                self.svc_status_var.set(f"Dienststatus: ⚠ {status}")
            else:
                self.svc_status_var.set("Dienststatus: ✗ Nicht installiert")
        except Exception as e:
            self.svc_status_var.set(f"Dienststatus: Fehler – {e}")

    # ── Autostart + Selbsttest ──────────────────────────────────────

    def _oauth_config_incomplete(self) -> bool:
        """True, wenn der gewählte Modus Client-ID/Secret braucht, die Felder aber leer sind."""
        mode = (self.auth_mode_var.get() or "none").strip().lower()
        cid = self.client_id_var.get().strip()
        csec = self.client_secret_var.get().strip()
        if mode in ("github", "google"):
            return not cid or not csec
        if mode == "oidc":
            return not cid or not csec
        return False

    def _stack_start_mcp_and_self_test(self) -> None:
        """Nach manuellem „Stack starten“: MCP starten, dann Selbsttest (nicht beim App-Öffnen)."""
        self._switch_section("Betrieb")
        self._ops("")
        self._ops("══════════════════════════════════════")
        self._ops("  STACK STARTEN: MCP Server wird gestartet …")
        self._ops("══════════════════════════════════════")
        if self._oauth_config_incomplete():
            self._ops("")
            self._ops(
                "Hinweis: Auth-Modus erfordert Client-ID und Client Secret, die noch fehlen."
            )
            self._ops(
                "Bitte unter „Auth/Connector“ eintragen und ggf. „OAuth im Keystore speichern“, "
                "dann erneut „Stack starten“."
            )
            self._ops("Server und Selbsttest werden nicht ausgeführt, bis die Konfiguration vollständig ist.")
            self.status_var.set("Status: OAuth/Konfiguration unvollständig – Server nicht gestartet")
            return
        if not self.start_server():
            self._ops("Selbsttest wird übersprungen (MCP-Server wurde nicht gestartet).")
            return
        self._test_attempt = 0
        self.after(1500, self._schedule_health_check)

    def _schedule_health_check(self) -> None:
        """Poll port until server is ready, then trigger tests."""
        self._test_attempt += 1
        port = int(self.port_var.get().strip() or "8766")

        if self._test_attempt > 12:
            self._ops("")
            self._ops("FEHLER: Server antwortet nicht nach 12 Sekunden.")
            self._ops("Bitte manuell prüfen (Betrieb → Nur MCP Server starten).")
            self.status_var.set("Status: Server-Start fehlgeschlagen")
            return

        if self._check_port_open(port):
            self._ops(f"Server lauscht auf Port {port} – starte Selbsttest ...")
            self.after(600, lambda: threading.Thread(target=self._run_self_test, daemon=True).start())
        else:
            self._ops(f"  Warte auf Port {port} ... (Versuch {self._test_attempt}/12)")
            self.after(1000, self._schedule_health_check)

    def _check_port_open(self, port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            return False

    def _run_self_test(self) -> None:
        """Execute all self-tests in a background thread."""
        results: list[tuple[str, bool, str]] = []
        port = self.port_var.get().strip() or "8766"
        host = self.host_var.get().strip() or "127.0.0.1"

        # ── 1. Server-Prozess ──
        alive = self.server_proc is not None and self.server_proc.poll() is None
        results.append(("Server-Prozess", alive,
                         f"PID {self.server_proc.pid}" if alive else "Nicht gestartet"))

        # ── 2. Port erreichbar ──
        port_ok = self._check_port_open(int(port))
        results.append(("Port erreichbar", port_ok, f"{host}:{port}"))

        # ── 3. OAuth-Discovery-Endpunkt ──
        auth_mode = self.auth_mode_var.get().strip() or "none"
        oauth_ok = False
        oauth_detail = ""
        if auth_mode == "bearer":
            oauth_ok = True
            oauth_detail = "Bearer-Modus (kein OAuth-Discovery)"
        else:
            try:
                url = f"http://{host}:{port}/.well-known/oauth-authorization-server"
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    oauth_ok = resp.status == 200
                    oauth_detail = f"HTTP {resp.status} OK"
            except urllib.error.HTTPError as exc:
                oauth_ok = exc.code in (200, 301, 302)
                oauth_detail = f"HTTP {exc.code}"
            except Exception as exc:
                oauth_detail = str(exc)[:80]
        results.append(("OAuth Discovery", oauth_ok, oauth_detail))

        # ── 4. MCP-Endpoint antwortet ──
        mcp_ok = False
        mcp_detail = ""
        mcp_path = (self.path_var.get().strip() or "/mcp").strip()
        if not mcp_path.startswith("/"):
            mcp_path = "/" + mcp_path
        try:
            url = f"http://{host}:{port}{mcp_path}"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                mcp_ok = True
                mcp_detail = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            mcp_ok = exc.code in (401, 405, 406, 415)
            mcp_detail = f"HTTP {exc.code} (Server antwortet)"
        except Exception as exc:
            mcp_detail = str(exc)[:80]
        results.append((f"MCP Endpoint {mcp_path}", mcp_ok, mcp_detail))

        # ── 5. Policy geladen ──
        policy: dict = {}
        policy_ok = False
        policy_detail = ""
        try:
            policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            roots = policy.get("roots", [])
            mode = policy.get("permissions", {}).get("mode", "?")
            policy_ok = isinstance(roots, list) and isinstance(policy.get("permissions"), dict)
            policy_detail = f"{len(roots)} Root(s), Mode: {mode}"
        except Exception as exc:
            policy_detail = str(exc)[:80]
        results.append(("Policy geladen", policy_ok, policy_detail))

        # ── 6. list_directory – erstes Root auflisten ──
        list_ok = False
        list_detail = ""
        try:
            roots_list = policy.get("roots", []) if isinstance(policy.get("roots"), list) else []
            if not roots_list:
                list_ok = True
                list_detail = "Keine Roots (Secure-Default) — MCP list_directory nicht getestet"
            else:
                blocked_dirs = {d.lower() for d in policy.get("blocked", {}).get("dir_names", [])}
                first_root = Path(roots_list[0])
                if first_root.exists() and first_root.is_dir():
                    visible = [e for e in first_root.iterdir()
                               if e.name.lower() not in blocked_dirs]
                    list_ok = len(visible) > 0
                    list_detail = f"{len(visible)} Einträge sichtbar in {first_root}"
                else:
                    list_detail = f"{first_root} existiert nicht"
        except Exception as exc:
            list_detail = str(exc)[:80]
        results.append(("list_directory", list_ok, list_detail))

        # ── 7. search_files – bekannte Datei suchen ──
        search_ok = False
        search_detail = ""
        try:
            for name in ("README.md", "README_CURSOR_START_HERE.md", "requirements.txt", "Visions.txt"):
                p = BASE_DIR / name
                if p.is_file():
                    search_ok = True
                    search_detail = f"{name} gefunden in {BASE_DIR.name}/"
                    break
            if not search_ok:
                for root_str in policy.get("roots", []):
                    p = Path(root_str)
                    if p.exists():
                        found = next(p.glob("*.md"), None) or next(p.glob("*.txt"), None)
                        if found:
                            search_ok = True
                            search_detail = f"{found.name} gefunden in {p}"
                            break
                if not search_ok:
                    search_detail = "Keine durchsuchbare Datei gefunden"
        except Exception as exc:
            search_detail = str(exc)[:80]
        results.append(("search_files", search_ok, search_detail))

        # ── 8. read_file – Policy-Datei lesen ──
        read_ok = False
        read_detail = ""
        try:
            if POLICY_FILE.exists():
                content = POLICY_FILE.read_text(encoding="utf-8")
                read_ok = len(content) > 10
                read_detail = f"mcp_policy.json lesbar ({len(content)} Bytes)"
            else:
                read_detail = "Policy-Datei nicht vorhanden"
        except Exception as exc:
            read_detail = str(exc)[:80]
        results.append(("read_file", read_ok, read_detail))

        # ── 9. Blockierlisten aktiv ──
        block_ok = False
        block_detail = ""
        try:
            blocked = policy.get("blocked", {})
            d = len(blocked.get("dir_names", []))
            s = len(blocked.get("suffixes", []))
            t = len(blocked.get("name_contains", []))
            block_ok = d > 0 and s > 0 and t > 0
            block_detail = f"{d} Ordner, {s} Endungen, {t} Name-Tokens gesperrt"
        except Exception as exc:
            block_detail = str(exc)[:80]
        results.append(("Blockierlisten aktiv", block_ok, block_detail))

        # ── 10. Schreibschutz prüfen ──
        write_ok = False
        write_detail = ""
        try:
            mode = policy.get("permissions", {}).get("mode", "read_only")
            if mode == "read_only":
                write_ok = True
                write_detail = "Schreibschutz aktiv – write_file/delete_path blockiert"
            else:
                write_ok = True
                write_detail = f"ACHTUNG: Schreibmodus '{mode}' – write_file erlaubt!"
        except Exception as exc:
            write_detail = str(exc)[:80]
        results.append(("Schreibschutz", write_ok, write_detail))

        # ── 11. Cloudflare Tunnel ──
        tunnel_ok = False
        tunnel_detail = ""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-Service cloudflared -ErrorAction SilentlyContinue).Status"],
                capture_output=True, text=True, timeout=5
            )
            status = r.stdout.strip()
            tunnel_ok = status == "Running"
            tunnel_detail = f"cloudflared: {status}" if status else "Dienst nicht installiert"
        except Exception as exc:
            tunnel_detail = str(exc)[:80]
        results.append(("Cloudflare Tunnel", tunnel_ok, tunnel_detail))

        # ── 12. Implicit-Deny (write_allow_paths) ──
        ideny_ok = False
        ideny_detail = ""
        try:
            perms = policy.get("permissions", {})
            pmode = perms.get("mode", "read_only")
            wap = perms.get("write_allow_paths", [])
            if pmode == "read_only":
                ideny_ok = True
                ideny_detail = "read_only Modus – Schreibschutz aktiv"
            elif isinstance(wap, list) and len(wap) > 0:
                ideny_ok = True
                ideny_detail = f"write_allow_paths: {len(wap)} Pfad(e) konfiguriert"
            else:
                ideny_detail = "WARNUNG: read_write ohne write_allow_paths – alles beschreibbar!"
        except Exception as exc:
            ideny_detail = str(exc)[:80]
        results.append(("Implicit-Deny Schreibschutz", ideny_ok, ideny_detail))

        # ── 13. Pfad-Normalisierung ──
        adv = policy.get("advanced", {})
        pnorm_ok = bool(adv.get("path_normalization_enabled", True)) if isinstance(adv, dict) else True
        results.append(("Pfad-Normalisierung", pnorm_ok,
                        "Aktiv (8.3/ADS/UNC-Schutz)" if pnorm_ok else "WARNUNG: Deaktiviert"))

        # ── 14. Kindpfad-Prüfung ──
        dcheck_ok = bool(adv.get("recursive_delete_check_children", True)) if isinstance(adv, dict) else True
        results.append(("Kindpfad-Prüfung (delete)", dcheck_ok,
                        "Aktiv" if dcheck_ok else "WARNUNG: Deaktiviert"))

        # ── 15. Schreiblimit ──
        mwb = int(adv.get("max_write_bytes", 5000000)) if isinstance(adv, dict) else 5000000
        wlimit_ok = mwb > 0
        results.append(("Schreiblimit", wlimit_ok,
                        f"{mwb:,} Bytes" if wlimit_ok else "WARNUNG: Unbegrenzt (0)"))

        # ── 16. Rate-State persistent ──
        rs_path = CONFIG_DIR / "rate_state.json"
        rs_exists = rs_path.exists()
        results.append(("Rate-State persistent", True,
                        "rate_state.json vorhanden" if rs_exists else "Noch nicht erstellt (normal bei erstem Start)"))

        # ── 17. SHA256 Startup-Integrität (Primärprüfung im MCP-Prozess) ──
        integ_ok = False
        integ_detail = ""
        try:
            marker_path = CONFIG_DIR / "policy_integrity_startup.json"
            adv_pol = policy.get("advanced", {}) if isinstance(policy.get("advanced"), dict) else {}
            pi_raw = adv_pol.get("policy_integrity")
            if isinstance(pi_raw, dict):
                integ_enabled = bool(pi_raw.get("enabled", True))
            else:
                integ_enabled = True
            if not integ_enabled:
                integ_ok = True
                integ_detail = "Integrität in Policy deaktiviert – kein SHA256-Zwang"
            elif not marker_path.is_file():
                integ_ok = False
                integ_detail = "Kein policy_integrity_startup.json – MCP nach Update neu starten"
            else:
                marker = json.loads(marker_path.read_text(encoding="utf-8"))
                if not marker.get("startup_ok", True):
                    integ_ok = False
                    integ_detail = f"Marker meldet Fehler: {marker.get('error', '?')}"
                elif not marker.get("integrity_enabled", True):
                    integ_ok = True
                    integ_detail = "Integrität war beim Start deaktiviert (Marker)"
                else:
                    cur_p = hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest()
                    if cur_p != marker.get("policy_sha256"):
                        integ_ok = False
                        integ_detail = "Policy SHA256 ≠ Startup (Datei nach Serverstart geändert?)"
                    else:
                        inc_ks = bool(marker.get("include_keystore_files", True))
                        if inc_ks:
                            cur_ke = (
                                hashlib.sha256(KEYSTORE_PATH.read_bytes()).hexdigest()
                                if KEYSTORE_PATH.is_file()
                                else ""
                            )
                            cur_sa = (
                                hashlib.sha256(SALT_PATH.read_bytes()).hexdigest()
                                if SALT_PATH.is_file()
                                else ""
                            )
                            if cur_ke != marker.get("keystore_enc_sha256") or cur_sa != marker.get(
                                "keystore_salt_sha256"
                            ):
                                integ_ok = False
                                integ_detail = "Keystore/Salt SHA256 ≠ Startup"
                            else:
                                integ_ok = True
                                integ_detail = (
                                    f"Primärprüfung konsistent policy={cur_p[:16]}… keystore ok"
                                )
                        else:
                            integ_ok = True
                            integ_detail = f"Primärprüfung konsistent policy={cur_p[:16]}… (ohne Keystore-Dateien)"
        except Exception as exc:
            integ_detail = str(exc)[:120]
        results.append(("SHA256 Startup-Integrität", integ_ok, integ_detail))

        # Ergebnis im Main-Thread anzeigen
        self.after(0, lambda res=results: self._display_test_results(res))

    def _display_test_results(self, results: list[tuple[str, bool, str]]) -> None:
        """Show test results in ops log and status bar."""
        self._ops("")
        self._ops("══════════════════════════════════════")
        self._ops("  SELBSTTEST – ERGEBNISSE")
        self._ops("══════════════════════════════════════")

        passed = 0
        failed = 0
        for name, ok, detail in results:
            icon = "OK" if ok else "FEHLER"
            prefix = "  [+]" if ok else "  [-]"
            self._ops(f"{prefix} {name}: {icon} – {detail}")
            if ok:
                passed += 1
            else:
                failed += 1

        total = passed + failed
        self._ops("")
        if failed == 0:
            self._ops(f"  >>> ALLE {total} TESTS BESTANDEN <<<")
            self.status_var.set(f"Status: Stack gestartet – {total}/{total} Tests OK")
        else:
            self._ops(f"  >>> {passed}/{total} OK, {failed} FEHLER <<<")
            self.status_var.set(f"Status: Stack gestartet – {passed}/{total} Tests OK, {failed} Fehler")
        self._ops("══════════════════════════════════════")
        self._ops("")

    def _help_content(self) -> str:
        """Hilfetext locale-abhängig laden: HILFE.md (DE) oder HELP.md (EN, Stub)."""
        scripts_dir = Path(__file__).resolve().parent
        locale = mcc_locale()
        primary = scripts_dir / ("HELP.md" if locale == "en" else "HILFE.md")
        fallback = scripts_dir / "HILFE.md"
        help_path = primary if primary.exists() else fallback
        if help_path.exists():
            text = help_path.read_text(encoding="utf-8")
            try:
                text = text.replace("{mcp_url}", self._current_mcp_url())
            except Exception:
                pass
            return text
        return "Help file not found: " + str(help_path)

    def _refresh_help_text(self) -> None:
        self.help_text.delete("1.0", tk.END)
        self.help_text.insert("1.0", self._help_content())

    def _save_help_file(self) -> None:
        target = filedialog.asksaveasfilename(
            title="Hilfe speichern",
            initialdir=str(EXPORT_DIR),
            initialfile="mcc_guardian_hilfe.txt",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt")],
        )
        if not target:
            return
        Path(target).write_text(self._help_content(), encoding="utf-8")
        self.status_var.set(f"Status: Hilfe gespeichert → {target}")

    def _split_lines(self, text_widget: tk.Text) -> list[str]:
        raw = text_widget.get("1.0", tk.END)
        out = []
        for line in raw.splitlines():
            value = line.strip()
            if value:
                out.append(value)
        return out

    def _set_lines(self, text_widget: tk.Text, values: list[str]) -> None:
        text_widget.delete("1.0", tk.END)
        text_widget.insert("1.0", "\n".join(values))

    def _read_policy_file(self) -> dict:
        if not POLICY_FILE.exists():
            return dict(DEFAULT_POLICY)
        try:
            data = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
            return dict(DEFAULT_POLICY)
        except Exception:
            return dict(DEFAULT_POLICY)

    def _guardian_ui_settings_path(self) -> Path:
        return CONFIG_DIR / "guardian_ui.json"

    def _load_guardian_ui_settings(self) -> None:
        p = self._guardian_ui_settings_path()
        if not p.is_file():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return
            self._suppress_mon_persist = True
            if "mon_filter_tool" in data:
                self._mon_filter_tool.set(str(data["mon_filter_tool"]))
            if "mon_filter_outcome" in data:
                self._mon_filter_outcome.set(str(data["mon_filter_outcome"]))
            if "mon_filter_search" in data:
                self._mon_filter_search.set(str(data["mon_filter_search"]))
            if "mon_time_minutes" in data:
                try:
                    self._mon_time_minutes.set(int(data["mon_time_minutes"]))
                except (TypeError, ValueError):
                    pass
            if "mon_show_full_paths" in data:
                self._mon_show_full_paths.set(bool(data["mon_show_full_paths"]))
            if "public_base_url" in data and hasattr(self, "public_url_var"):
                self._suppress_pub_url_persist = True
                try:
                    self.public_url_var.set(str(data["public_base_url"]))
                finally:
                    self._suppress_pub_url_persist = False
            if "oauth_client_secret_rotated_at_utc" in data:
                raw_rot = str(data["oauth_client_secret_rotated_at_utc"]).strip()
                if raw_rot:
                    self._oauth_secret_rotated_iso = raw_rot
                    self._sync_oauth_rotation_label()
            if "ui_locale" in data:
                loc = str(data["ui_locale"]).strip().lower()
                if loc in ("de", "en"):
                    set_ui_locale(loc)
                    if hasattr(self, "_locale_menu_var"):
                        self._locale_menu_var.set(loc)
        except Exception:
            pass
        finally:
            self._suppress_mon_persist = False

    def _save_guardian_ui_settings(self) -> None:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            p = self._guardian_ui_settings_path()
            data: dict[str, Any] = {}
            if p.is_file():
                try:
                    prev = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(prev, dict):
                        data = dict(prev)
                except Exception:
                    pass
            data.update(
                {
                    "mon_filter_tool": self._mon_filter_tool.get(),
                    "mon_filter_outcome": self._mon_filter_outcome.get(),
                    "mon_filter_search": self._mon_filter_search.get(),
                    "mon_time_minutes": int(self._mon_time_minutes.get() or 0),
                    "mon_show_full_paths": bool(self._mon_show_full_paths.get()),
                }
            )
            if hasattr(self, "public_url_var"):
                data["public_base_url"] = self.public_url_var.get().strip()
            rot = getattr(self, "_oauth_secret_rotated_iso", "").strip()
            if rot:
                data["oauth_client_secret_rotated_at_utc"] = rot
            data["ui_locale"] = mcc_locale()
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    def _save_public_base_url_ui(self) -> None:
        self._save_guardian_ui_settings()
        self.status_var.set("Status: Public Base URL in guardian_ui.json gespeichert")

    def _update_auth_mode_hint(self) -> None:
        if not hasattr(self, "_auth_mode_hint_var"):
            return
        m = (self.auth_mode_var.get() or "none").strip().lower()
        self._auth_mode_hint_var.set(_AUTH_MODE_HINTS_DE.get(m, _AUTH_MODE_HINTS_DE["none"]))

    def _sync_oauth_rotation_label(self) -> None:
        if not hasattr(self, "_oauth_rot_hint_lbl"):
            return
        iso = getattr(self, "_oauth_secret_rotated_iso", "").strip()
        if not iso:
            self._oauth_rot_hint_lbl.config(
                text="Secret-Rotation: Zeitstempel erscheint, sobald Sie „OAuth im Keystore speichern“ nutzen."
            )
        else:
            self._oauth_rot_hint_lbl.config(
                text=f"Client Secret zuletzt im Keystore gespeichert (UTC): {iso}"
            )

    def _open_today_access_log(self) -> None:
        path = _today_access_log()
        if not path.is_file():
            messagebox.showinfo(
                "Access-Log",
                f"Noch keine Datei für heute:\n{path}\n\nSie entsteht mit dem ersten MCP-Zugriff.",
                parent=self,
            )
            return
        try:
            os.startfile(path)  # type: ignore[attr-defined]
            self.status_var.set(f"Status: Access-Log geöffnet — {path.name}")
        except OSError as exc:
            messagebox.showerror("Access-Log", f"Konnte nicht geöffnet werden:\n{exc}", parent=self)

    def _oauth_connectivity_test(self) -> None:
        lines: list[str] = []
        try:
            req = urllib.request.Request("https://github.com", headers={"User-Agent": "MCC-Guardian-OAuth-Test/1.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                lines.append(f"github.com erreichbar (HTTP {resp.status}).")
        except Exception as exc:
            messagebox.showerror("OAuth-Test", f"GitHub nicht erreichbar:\n{exc}", parent=self)
            return
        mode = (self.auth_mode_var.get() or "").strip().lower()
        if mode != "github":
            lines.append(f"Auth-Modus „{mode}“: Autorisierungs-URL-Test ist für GitHub OAuth definiert.")
            messagebox.showinfo("OAuth-Test", "\n".join(lines), parent=self)
            return
        cid = self.client_id_var.get().strip()
        cb = self.callback_var.get().strip()
        if not cid:
            messagebox.showwarning("OAuth-Test", "Client ID fehlt.", parent=self)
            return
        if not cb:
            messagebox.showwarning("OAuth-Test", "Callback-URL leer — Public Base URL setzen.", parent=self)
            return
        scopes = self.scopes_var.get().strip() or "read:user"
        q = urlencode(
            {
                "client_id": cid,
                "redirect_uri": cb,
                "scope": scopes,
                "response_type": "code",
                "state": "mcc_oauth_probe",
            }
        )
        auth_url = f"https://github.com/login/oauth/authorize?{q}"
        try:
            req2 = urllib.request.Request(auth_url, headers={"User-Agent": "MCC-Guardian-OAuth-Test/1.0"})
            with urllib.request.urlopen(req2, timeout=20) as resp2:
                lines.append(f"authorize-URL: HTTP {resp2.status} (Redirects von urllib ggf. gefolgt).")
        except urllib.error.HTTPError as he:
            lines.append(f"authorize-URL: HTTP {he.code} (Antwort von GitHub, ggf. Login-/Fehlerseite).")
        except Exception as exc:
            lines.append(f"authorize-URL: {exc}")
        messagebox.showinfo("OAuth-Test", "\n".join(lines), parent=self)

    def _bind_keyboard_shortcuts(self) -> None:
        self.bind_all("<Control-s>", self._shortcut_save_policy)
        self.bind_all("<Control-S>", self._shortcut_save_policy)
        self.bind_all("<Control-e>", self._shortcut_export)
        self.bind_all("<Control-E>", self._shortcut_export)
        self.bind_all("<Control-q>", self._shortcut_quit)
        self.bind_all("<Control-Q>", self._shortcut_quit)

    def _shortcut_save_policy(self, _event: object | None = None) -> str:
        self.save_policy_from_ui()
        return "break"

    def _shortcut_export(self, _event: object | None = None) -> str:
        self.export_now()
        return "break"

    def _shortcut_quit(self, _event: object | None = None) -> str:
        self._on_close()
        return "break"

    def load_policy_to_ui(self) -> None:
        self._suppress_policy_dirty = True
        try:
            policy = self._read_policy_file()

            self._suppress_mode_trace = True
            self.mode_var.set(str(policy.get("permissions", {}).get("mode", "read_only")))
            self._suppress_mode_trace = False
            self._set_lines(self.roots_txt, [str(v) for v in policy.get("roots", [])])
            self._set_lines(self.write_allow_txt, [str(v) for v in policy.get("permissions", {}).get("write_allow_paths", [])])
            self._set_lines(self.write_deny_txt, [str(v) for v in policy.get("permissions", {}).get("write_deny_paths", [])])

            blocked = policy.get("blocked", {})
            self._set_lines(self.dir_names_txt, [str(v) for v in blocked.get("dir_names", [])])
            self._set_lines(self.path_parts_txt, [str(v) for v in blocked.get("path_parts", [])])
            self._set_lines(self.suffixes_txt, [str(v) for v in blocked.get("suffixes", [])])
            self._set_lines(self.file_names_txt, [str(v) for v in blocked.get("file_names", [])])
            self._set_lines(self.name_contains_txt, [str(v) for v in blocked.get("name_contains", [])])

            self._load_tool_registry_to_ui(policy)

            self.status_var.set("Status: Policy geladen")

            if hasattr(self, "_adv_max_write"):
                self._load_advanced_from_policy()
        finally:
            self._suppress_policy_dirty = False
        self._clear_policy_dirty()
        self._update_policy_risk()

    def reset_policy_defaults(self) -> None:
        POLICY_FILE.write_text(json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2), encoding="utf-8")
        self.load_policy_to_ui()
        self.status_var.set("Status: Standard-Policy wiederhergestellt")

    def save_policy_from_ui(self) -> None:
        existing = self._read_policy_file()
        perms = {
            "mode": self.mode_var.get().strip() or "read_only",
            "write_allow_paths": self._split_lines(self.write_allow_txt),
            "write_deny_paths": self._split_lines(self.write_deny_txt),
        }
        old_perms = existing.get("permissions") if isinstance(existing.get("permissions"), dict) else {}
        if isinstance(old_perms, dict) and "agents" in old_perms:
            perms["agents"] = old_perms["agents"]
        policy: dict = {
            "roots": self._split_lines(self.roots_txt),
            "permissions": perms,
            "blocked": {
                "dir_names": self._split_lines(self.dir_names_txt),
                "path_parts": self._split_lines(self.path_parts_txt),
                "suffixes": self._split_lines(self.suffixes_txt),
                "file_names": self._split_lines(self.file_names_txt),
                "name_contains": self._split_lines(self.name_contains_txt),
            },
            "tool_registry": self._tool_registry_payload_from_ui(),
        }

        # managed_keys = Keys die NUR aus dem UI-State kommen und die alte Datei ueberschreiben.
        # rate_limit, client_blocklist, honeypot, advanced werden NICHT vom UI verwaltet,
        # deshalb stehen sie in managed_keys (Loop ueberspringt sie) und werden
        # separat via setdefault aus der alten Datei uebernommen.
        managed_keys = {
            "roots", "permissions", "blocked", "rate_limit", "client_blocklist",
            "honeypot", "advanced", "tool_registry",
        }
        for key, val in existing.items():
            if key not in managed_keys and key not in policy:
                policy[key] = val

        if "rate_limit" in existing:
            policy.setdefault("rate_limit", existing["rate_limit"])
        if "client_blocklist" in existing:
            policy.setdefault("client_blocklist", existing["client_blocklist"])
        if "honeypot" in existing:
            policy.setdefault("honeypot", existing["honeypot"])
        if "advanced" in existing:
            policy.setdefault("advanced", existing["advanced"])

        policy.pop("python_automation", None)

        tmp = tempfile.NamedTemporaryFile(
            mode="w", dir=str(POLICY_FILE.parent), suffix=".tmp", delete=False, encoding="utf-8"
        )
        tmp.write(json.dumps(policy, ensure_ascii=False, indent=2))
        tmp.close()
        os.replace(tmp.name, str(POLICY_FILE))
        self.status_var.set("Status: Policy gespeichert")
        self._ops("Policy gespeichert: " + str(POLICY_FILE))
        self._clear_policy_dirty()

    def _tool_registry_payload_from_ui(self) -> dict[str, Any]:
        disabled = [n for n, v in self._tool_toggle_vars.items() if not v.get()]
        prof = (self._tool_profile_var.get() or "standard").strip() or "standard"
        cp_out: dict[str, Any] = {}
        for k, v in self._tool_custom_profiles.items():
            if isinstance(v, dict) and isinstance(v.get("disabled_tools"), list):
                cp_out[str(k)] = {
                    "disabled_tools": [str(x) for x in v["disabled_tools"] if str(x).strip()],
                }
        return {
            "active_profile": prof,
            "disabled_tools": disabled,
            "custom_profiles": cp_out,
        }

    def _refresh_tool_profile_combo_values(self) -> None:
        if not hasattr(self, "_tool_profile_combo"):
            return
        names = ["standard"] + sorted(k for k in self._tool_custom_profiles.keys() if k != "standard")
        self._tool_profile_combo.configure(values=names)

    def _load_tool_registry_to_ui(self, policy: dict[str, Any]) -> None:
        if not self._tool_toggle_vars:
            return
        tr = policy.get("tool_registry") if isinstance(policy.get("tool_registry"), dict) else {}
        disabled_set: set[str] = set()
        dt = tr.get("disabled_tools")
        if isinstance(dt, list):
            disabled_set = {str(x).strip() for x in dt if str(x).strip()}
        for name, var in self._tool_toggle_vars.items():
            var.set(name not in disabled_set)
        self._tool_custom_profiles.clear()
        cp = tr.get("custom_profiles")
        if isinstance(cp, dict):
            for k, v in cp.items():
                if isinstance(v, dict) and isinstance(v.get("disabled_tools"), list):
                    self._tool_custom_profiles[str(k)] = {
                        "disabled_tools": [str(x) for x in v["disabled_tools"] if str(x).strip()],
                    }
        self._tool_profile_var.set(str(tr.get("active_profile", "standard") or "standard"))
        self._refresh_tool_profile_combo_values()

    def _tool_profile_apply(self) -> None:
        if not self._tool_toggle_vars:
            return
        name = (self._tool_profile_var.get() or "standard").strip() or "standard"
        if name == "standard":
            disabled_list: list[str] = []
        else:
            ent = self._tool_custom_profiles.get(name) or {}
            raw = ent.get("disabled_tools") if isinstance(ent, dict) else None
            disabled_list = list(raw) if isinstance(raw, list) else []
        ds = {str(x).strip() for x in disabled_list if str(x).strip()}
        for tname, var in self._tool_toggle_vars.items():
            var.set(tname not in ds)
        self._mark_policy_dirty()

    def _tool_profile_save_as(self) -> None:
        if not self._tool_toggle_vars:
            return
        name = simpledialog.askstring("Profil speichern", "Name des Tool-Profils:", parent=self)
        if not name or not str(name).strip():
            return
        name = str(name).strip()
        disabled = [n for n, v in self._tool_toggle_vars.items() if not v.get()]
        self._tool_custom_profiles[name] = {"disabled_tools": disabled}
        self._tool_profile_var.set(name)
        self._refresh_tool_profile_combo_values()
        self._mark_policy_dirty()

    def _export_settings_snapshot(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Einstellungs-Snapshot exportieren",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialdir=str(EXPORT_DIR),
            initialfile="mcc_settings_snapshot.json",
        )
        if not path:
            return
        snap: dict[str, Any] = {
            "mcc_settings_snapshot_version": MCC_SETTINGS_SNAPSHOT_VERSION,
            "exported_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policy": self._read_policy_file(),
            "listen": {
                "mcp_port": self.port_var.get().strip(),
                "mcp_host": self.host_var.get().strip(),
                "mcp_path": self.path_var.get().strip(),
            },
        }
        gu = self._guardian_ui_settings_path()
        if gu.is_file():
            try:
                snap["guardian_ui"] = json.loads(gu.read_text(encoding="utf-8"))
            except Exception:
                snap["guardian_ui"] = {}
        else:
            snap["guardian_ui"] = {}
        if BLOCKED_IPS_FILE.is_file():
            try:
                snap["blocked_ips"] = json.loads(BLOCKED_IPS_FILE.read_text(encoding="utf-8"))
            except Exception:
                snap["blocked_ips"] = {}
        else:
            snap["blocked_ips"] = {}
        Path(path).write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
        self.status_var.set(f"Status: Snapshot exportiert → {path}")
        self._ops(f"Settings-Snapshot exportiert: {path}")

    def _apply_settings_snapshot(self, data: dict[str, Any]) -> None:
        new_pol = data.get("policy")
        if not isinstance(new_pol, dict):
            return
        POLICY_FILE.write_text(json.dumps(new_pol, ensure_ascii=False, indent=2), encoding="utf-8")
        listen = data.get("listen")
        if isinstance(listen, dict):
            if listen.get("mcp_port"):
                self.port_var.set(str(listen["mcp_port"]).strip())
            if listen.get("mcp_host"):
                self.host_var.set(str(listen["mcp_host"]).strip())
            if listen.get("mcp_path"):
                self.path_var.set(str(listen["mcp_path"]).strip())
        gui = data.get("guardian_ui")
        if isinstance(gui, dict):
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self._guardian_ui_settings_path().write_text(
                json.dumps(gui, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            self._load_guardian_ui_settings()
        bi = data.get("blocked_ips")
        if isinstance(bi, dict):
            BLOCKED_IPS_FILE.write_text(json.dumps(bi, ensure_ascii=False, indent=2), encoding="utf-8")
            if hasattr(self, "_refresh_blocklist_view"):
                self._refresh_blocklist_view()
        self.load_policy_to_ui()
        self.status_var.set("Status: Snapshot importiert")
        self._ops("Settings-Snapshot angewendet.")

    def _import_settings_snapshot(self) -> None:
        path = filedialog.askopenfilename(title="Einstellungs-Snapshot importieren", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            messagebox.showerror("Import", f"Datei konnte nicht gelesen werden:\n{exc}", parent=self)
            return
        if not isinstance(data, dict):
            messagebox.showerror("Import", "Ungültiges JSON-Objekt.", parent=self)
            return
        ver = data.get("mcc_settings_snapshot_version")
        if ver != MCC_SETTINGS_SNAPSHOT_VERSION:
            if not messagebox.askyesno(
                "Import",
                f"Snapshot-Version ist {ver!r} (erwartet {MCC_SETTINGS_SNAPSHOT_VERSION}).\nTrotzdem fortfahren?",
                parent=self,
            ):
                return
        new_pol = data.get("policy")
        if not isinstance(new_pol, dict):
            messagebox.showerror("Import", "Snapshot enthält kein gültiges „policy“-Objekt.", parent=self)
            return
        cur_lines = json.dumps(self._read_policy_file(), ensure_ascii=False, indent=2).splitlines(keepends=True)
        new_lines = json.dumps(new_pol, ensure_ascii=False, indent=2).splitlines(keepends=True)
        diff = "".join(difflib.unified_diff(cur_lines, new_lines, fromfile="aktuell", tofile="import"))
        top = tk.Toplevel(self)
        top.title("Import — Diff (Policy)")
        top.geometry("920x540")
        outer = ttk.Frame(top, padding=6)
        outer.pack(fill=tk.BOTH, expand=True)
        mid = ttk.Frame(outer)
        mid.pack(fill=tk.BOTH, expand=True)
        txt = tk.Text(mid, wrap=tk.NONE, font=("Consolas", 9))
        sy = ttk.Scrollbar(mid, orient="vertical", command=txt.yview)
        sx = ttk.Scrollbar(mid, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        txt.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)
        txt.insert("1.0", diff or "(Keine Text-Unterschiede in der JSON-Darstellung.)")
        btnf = ttk.Frame(outer)
        btnf.pack(fill=tk.X, pady=(8, 0))

        def _apply_import() -> None:
            top.destroy()
            self._apply_settings_snapshot(data)

        def _cancel_import() -> None:
            top.destroy()

        ttk.Button(btnf, text="Abbrechen", command=_cancel_import).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btnf, text="Import anwenden", command=_apply_import).pack(side=tk.RIGHT, padx=4)

    def _change_master_password_dialog(self) -> None:
        if not KEYSTORE_PATH.is_file():
            messagebox.showinfo("Master-Passwort", "Kein Keystore vorhanden.", parent=self)
            return
        old_pw = simpledialog.askstring("Master-Passwort", "Aktuelles Master-Passwort:", show="*", parent=self)
        if old_pw is None:
            return
        store = unlock_keystore(old_pw)
        if store is None:
            messagebox.showerror("Master-Passwort", "Passwort ungültig oder Keystore beschädigt.", parent=self)
            return
        new_pw = simpledialog.askstring(
            "Master-Passwort",
            "Neues Master-Passwort (mind. 10 Zeichen empfohlen):",
            show="*",
            parent=self,
        )
        if new_pw is None:
            return
        if len(new_pw) < 10:
            if not messagebox.askyesno(
                "Master-Passwort",
                "Das neue Passwort ist kurz (<10 Zeichen).\nTrotzdem verwenden?",
                parent=self,
            ):
                return
        new_pw2 = simpledialog.askstring("Master-Passwort", "Neues Passwort wiederholen:", show="*", parent=self)
        if new_pw2 is None or new_pw != new_pw2:
            messagebox.showerror("Master-Passwort", "Wiederholung stimmt nicht.", parent=self)
            return
        try:
            save_keystore(new_pw, store)
        except OSError as exc:
            messagebox.showerror("Master-Passwort", f"Speichern fehlgeschlagen:\n{exc}", parent=self)
            return
        self._master_password = new_pw
        self._keystore_store = store
        messagebox.showinfo("Master-Passwort", "Master-Passwort wurde geändert.", parent=self)
        self.status_var.set("Status: Master-Passwort geändert")

    def _export_keystore_plaintext_dialog(self) -> None:
        if self._keystore_store is None:
            messagebox.showerror("Export", "Keystore nicht entsperrt.", parent=self)
            return
        if not messagebox.askyesno(
            "Keystore Klartext-Export",
            "WARNUNG: Alle Schlüssel und OAuth-Daten werden UNVERSCHLÜSSELT in eine Datei geschrieben.\n\n"
            "Nur in einer vertrauenswürdigen Umgebung nutzen und die Datei nach dem Backup löschen.\n\n"
            "Fortfahren?",
            parent=self,
            icon="warning",
        ):
            return
        if not messagebox.askyesno(
            "Bestätigung",
            "Zweite Bestätigung: Klartext-Export wirklich durchführen?",
            parent=self,
            icon="warning",
        ):
            return
        pw = self._require_master_password()
        if not pw:
            return
        st = unlock_keystore(pw)
        if st is None:
            messagebox.showerror("Export", "Passwort ungültig.", parent=self)
            return
        out_path = filedialog.asksaveasfilename(
            title="Keystore Klartext exportieren",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialdir=str(EXPORT_DIR),
            initialfile="mcc_keystore_plain_EXPORT_SICHER_LOESCHEN.json",
        )
        if not out_path:
            return
        Path(out_path).write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
        messagebox.showwarning(
            "Export",
            f"Klartext gespeichert:\n{out_path}\n\nDatei sicher aufbewahren oder löschen.",
            parent=self,
        )
        self.status_var.set("Status: Keystore Klartext exportiert (sensible Datei!)")

    def _ops(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.ops_log.insert(tk.END, f"[{stamp}] {text}\n")
        self.ops_log.see(tk.END)

    def _clear_ops_log_ui_only(self) -> None:
        """Nur das Betriebslog-Textfeld leeren; JSON-Logs auf der Platte bleiben."""
        if not hasattr(self, "ops_log"):
            return
        self.ops_log.delete("1.0", tk.END)
        self.status_var.set("Status: Betriebslog-Anzeige geleert (JSON-Dateien unverändert)")

    def _health_mirror_to_ops_ui(self, rec: dict[str, Any]) -> None:
        """Health-Ergebnis zusätzlich zur JSONL-Datei im Betriebslog anzeigen (Hauptthread)."""
        if not hasattr(self, "ops_log"):
            return
        ts = str(rec.get("ts", ""))
        if len(ts) >= 19:
            ts = ts[:19].replace("T", " ")
        else:
            ts = ts or "?"
        passed = int(rec.get("passed", 0))
        failed = int(rec.get("failed", 0))
        self._ops(f"HEALTH ({ts} UTC): {passed} ok, {failed} mit Hinweis")
        for row in rec.get("results") or []:
            name = str(row.get("name", "?"))
            ok = bool(row.get("ok"))
            detail = str(row.get("detail", ""))
            tag = "OK" if ok else "!"
            self._ops(f"  [{tag}] {name}: {detail}")

    def _resolve_python_for_mcp_script(self) -> list[str] | None:
        """Kommando [Interpreter, …, script] für mcp_server.py.

        Bei PyInstaller-EXE ist sys.executable die GUI – der MCP-Server muss mit
        einem echten Python laufen. Es wird ein Interpreter gesucht, der
        ``import fastmcp`` ausführen kann.
        """
        script = str(BASE_DIR / "scripts" / "mcp_server.py")
        if not getattr(sys, "frozen", False):
            return [sys.executable, script]
        win = os.name == "nt"
        flags = subprocess.CREATE_NO_WINDOW if win else 0

        def can_import_fastmcp(py_cmd: list[str]) -> bool:
            try:
                r = subprocess.run(
                    py_cmd + ["-c", "import fastmcp"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    creationflags=flags,
                )
                return r.returncode == 0
            except Exception:
                return False

        for name in ("python", "python3"):
            exe = shutil.which(name)
            if exe and can_import_fastmcp([exe]):
                return [exe, script]
        launcher = shutil.which("py")
        if launcher and can_import_fastmcp([launcher, "-3"]):
            return [launcher, "-3", script]
        return None

    def _server_command(self):
        env = os.environ.copy()
        _base = str(BASE_DIR)
        env["MCC_GUARDIAN_BASE"] = _base
        env["MCC_BASE_DIR"] = _base
        env["PYTHONUNBUFFERED"] = "1"
        env["MCP_POLICY_FILE"] = str(POLICY_FILE)
        env["MCC_LOG_DIR"] = str(LOG_DIR)
        env["MCP_PORT"] = self.port_var.get().strip() or "8766"
        env["MCP_HOST"] = self.host_var.get().strip() or "127.0.0.1"
        env["MCP_PATH"] = self.path_var.get().strip() or "/mcp"

        for ek in list(env.keys()):
            if ek.upper().startswith("MCP_BEARER_KEY_"):
                del env[ek]
        for ek in ("MCP_AUTH_MODE", "MCP_PUBLIC_BASE_URL", "MCP_OAUTH_CLIENT_ID",
                    "MCP_OAUTH_CLIENT_SECRET", "MCP_OAUTH_SCOPES", "MCP_SECRETS_FILE"):
            env.pop(ek, None)

        mode = (self.auth_mode_var.get() or "none").strip().lower()

        secrets_dict: dict[str, Any] = {
            "auth_mode": mode,
            "public_base_url": self.public_url_var.get().strip(),
            "oauth_client_id": self.client_id_var.get().strip(),
            "oauth_client_secret": self.client_secret_var.get().strip(),
            "oauth_scopes": self.scopes_var.get().strip(),
        }

        if mode == "bearer" and self._keystore_store is not None:
            bearer_keys = {}
            for client_name, raw_key in self._keystore_store.items():
                key = str(raw_key).strip()
                if not key:
                    continue
                suffix = "".join(c if c.isalnum() else "_" for c in str(client_name)).strip("_").lower()
                if suffix:
                    bearer_keys[suffix] = key
            secrets_dict["bearer_keys"] = bearer_keys

        secrets_blob = json.dumps(secrets_dict).encode("utf-8")

        cmd = self._resolve_python_for_mcp_script()
        if cmd is None:
            return None, env, b""
        return cmd, env, secrets_blob

    def _close_mcp_server_log_fp(self) -> None:
        if self._mcp_server_log_fp is not None:
            try:
                self._mcp_server_log_fp.close()
            except OSError:
                pass
            self._mcp_server_log_fp = None

    def _append_mcp_log_tail_to_ops(self, n: int = 30) -> None:
        path = LOG_DIR / "mcp_server.out.log"
        if not path.exists():
            self._ops("(Kein mcp_server.out.log vorhanden.)")
            return
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            self._ops("— Letzte Zeilen aus mcp_server.out.log —")
            for line in lines[-n:]:
                self._ops("  " + line[:300])
        except Exception as exc:
            self._ops(f"(Log konnte nicht gelesen werden: {exc})")

    def _kill_stale_mcp_readonly_processes(self) -> None:
        """Beendet Prozesse, deren Kommandozeile ``mcp_server.py`` enthält.

        Wichtig: Der Start erfolgt oft als ``py -3 …\\mcp_server.py`` (Prozessname **py.exe**,
        nicht python.exe) — daher nur über CommandLine filtern, nicht über den Prozessnamen.
        """
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | Where-Object { "
                "$null -ne $_.CommandLine -and $_.CommandLine -like '*mcp_server.py*' "
                "} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }",
            ],
            check=False,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    def _kill_tcp_listener_on_port_windows(self, port: int) -> None:
        """Letzter Ausweg: Prozess beenden, der auf ``127.0.0.1:<port>`` im Zustand Listen lauscht."""
        if os.name != "nt":
            return
        ps = (
            "Get-NetTCPConnection -LocalPort %d -State Listen -ErrorAction SilentlyContinue "
            "| ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
            % port
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            check=False,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

    def _check_mcp_subprocess_alive(self) -> None:
        """Solange der Server läuft: regelmäßig poll(); bei Exit Log + Exit-Code ins Betriebslog."""
        if not self.server_proc:
            return
        if self.server_proc.poll() is None:
            self.after(2000, self._check_mcp_subprocess_alive)
            return
        code = self.server_proc.returncode
        self._ops("")
        self._ops(f"FEHLER: MCP-Server-Prozess beendet (Exit-Code {code}).")
        self._append_mcp_log_tail_to_ops()
        self.status_var.set("Status: Server-Start fehlgeschlagen")
        self._close_mcp_server_log_fp()
        self.server_proc = None
        self.server_start_time = None

    def start_server(self) -> bool:
        if self.server_proc and self.server_proc.poll() is None:
            self._ops("Server läuft bereits")
            self._disconnect_called = False
            return True

        port = int(self.port_var.get().strip() or "8766")
        if self._check_port_open(port):
            self._ops(
                f"Hinweis: Port {port} ist belegt (oft ein alter mcp_server.py ohne GUI). "
                "Beende verwaiste MCP-Server-Prozesse …"
            )
            self._kill_stale_mcp_readonly_processes()
            time.sleep(0.7)
            if self._check_port_open(port):
                self._ops(
                    "Port noch belegt. Versuch: Listener-Prozess beenden (Windows, TCP Listen) …"
                )
                self._kill_tcp_listener_on_port_windows(port)
                time.sleep(0.7)
            if self._check_port_open(port):
                self._ops(
                    f"FEHLER: Port {port} ist noch belegt. "
                    "Bitte den blockierenden Dienst beenden oder unter Policy/Betrieb einen anderen Port eintragen."
                )
                self.status_var.set(f"Status: Port {port} belegt")
                return False

        self.save_policy_from_ui()
        mode = self.auth_mode_var.get().strip() or "none"
        if mode in ("github", "google"):
            if not self.client_id_var.get().strip() or not self.client_secret_var.get().strip():
                self._ops(
                    f'Hinweis: Auth-Modus "{mode}" benötigt Client-ID und Client Secret '
                    '(oder auf "bearer"/"none" wechseln).'
                )
                self.status_var.set("Status: Konfiguration unvollständig")
                return False
        if mode == "oidc":
            if not self.client_id_var.get().strip() or not self.client_secret_var.get().strip():
                self._ops(
                    "Hinweis: OIDC benötigt Client-ID und Client Secret "
                    "(sowie MCP_OIDC_CONFIG_URL in der Umgebung)."
                )
                self.status_var.set("Status: Konfiguration unvollständig")
                return False
        command, env, secrets_blob = self._server_command()
        if command is None:
            self._ops(
                "Fehler: Kein Python mit installiertem „fastmcp“ gefunden. "
                "Bitte Python 3 installieren, pip install fastmcp ausführen und PATH prüfen "
                "(bei der .exe muss derselbe Interpreter nutzbar sein wie für die Entwicklung)."
            )
            self.status_var.set("Status: Server-Start fehlgeschlagen")
            return False
        self._close_mcp_server_log_fp()
        out_file = (LOG_DIR / "mcp_server.out.log").open("a", encoding="utf-8")
        self._mcp_server_log_fp = out_file
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            # Secrets per Datei übergeben: zuverlässiger als stdin (Windows/Race/isatty).
            if secrets_blob:
                tf = tempfile.NamedTemporaryFile(
                    mode="wb", delete=False, prefix="mcc_mcp_", suffix=".json"
                )
                try:
                    tf.write(secrets_blob)
                    tf.flush()
                    if hasattr(os, "fsync"):
                        try:
                            os.fsync(tf.fileno())
                        except OSError:
                            pass
                finally:
                    tf.close()
                env["MCP_SECRETS_FILE"] = tf.name
            self.server_proc = subprocess.Popen(
                command,
                env=env,
                cwd=str(BASE_DIR),
                stdout=out_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=flags,
            )
            self.server_start_time = datetime.now(timezone.utc)
            self.status_var.set("Status: MCP Server gestartet")
            mode = "readonly"
            label = "Readonly"
            self._ops(f"Server gestartet ({label}) PID={self.server_proc.pid}")
            try:
                pol_sha = hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest()
                self._ops(f"Policy-Datei SHA256 (Referenz nach Speichern/Start): {pol_sha}")
            except OSError as exc:
                self._ops(f"Hinweis: Policy-Datei nicht lesbar für SHA256: {exc}")
            for ks_label, ks_path in (
                ("keystore.enc", KEYSTORE_PATH),
                ("keystore.salt", SALT_PATH),
            ):
                try:
                    if ks_path.is_file():
                        ks_sha = hashlib.sha256(ks_path.read_bytes()).hexdigest()
                        self._ops(f"{ks_label} SHA256 (Integrität): {ks_sha}")
                except OSError as exc:
                    self._ops(f"Hinweis: {ks_label} nicht lesbar für SHA256: {exc}")
            self.after(700, self._check_mcp_subprocess_alive)
            self._disconnect_called = False
            return True
        except Exception as e:
            self._ops(f"Fehler: Server start failed - {e}")
            self._close_mcp_server_log_fp()
            return False

    def stop_server(self) -> None:
        if self.server_proc and self.server_proc.poll() is None:
            proc = self.server_proc
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            self._ops(f"Server gestoppt PID={proc.pid}")
        self.server_proc = None
        self.server_start_time = None
        self._close_mcp_server_log_fp()
        self.status_var.set("Status: MCP Server gestoppt")

    def _parse_tunnel_url(self) -> str:
        u = self.public_url_var.get().strip().rstrip("/")
        return u or ""

    def start_tunnel(self) -> None:
        self._ops("Tunnel: optionaler externer Dienst — nicht Teil von MCC Lite.")

    def update_tunnel_url(self) -> None:
        base = self.public_url_var.get().strip().rstrip("/")
        if base:
            self.url_var.set(f"Tunnel-URL: {base}/mcp")
        else:
            self.url_var.set("Tunnel-URL: — (nur lokal)")

    def stop_tunnel(self) -> None:
        self._ops("Tunnel: nicht konfiguriert oder extern betrieben.")

    def start_stack(self) -> None:
        self._stack_start_mcp_and_self_test()
        self.update_tunnel_url()
        if self.server_proc is not None and self.server_proc.poll() is None:
            self.status_var.set("Status: Stack gestartet")

    def stop_stack(self) -> None:
        self.stop_server()
        self.update_tunnel_url()
        self.status_var.set("Status: Stack gestoppt")

    def _load_events(self) -> list[dict]:
        path = _today_access_log()
        if not path.exists():
            return []
        rows = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            raw = line.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return rows[-5000:]

    def _event_client(self, event: dict) -> str:
        cn = event.get("client_name")
        if cn:
            return str(cn)
        client = event.get("client_id")
        return str(client) if client else "(kein client_id)"

    def _event_http(self, event: dict) -> dict:
        return event.get("http") or {}

    def _event_ip(self, event: dict) -> str:
        if event.get("effective_ip"):
            return str(event["effective_ip"])
        http = self._event_http(event)
        for key in ("cf_connecting_ip", "x_forwarded_for", "client"):
            value = http.get(key)
            if value:
                return str(value)
        return "-"

    def _event_country(self, event: dict) -> str:
        if not self._adv_geo_tracking.get():
            return ""
        http = self._event_http(event)
        return str(http.get("cf_ipcountry") or http.get("cf-ipcountry") or "")

    def _event_ua(self, event: dict) -> str:
        value = self._event_http(event).get("user_agent")
        return str(value) if value else "-"

    def _event_path(self, event: dict) -> str:
        args = event.get("args") or {}
        return str(args.get("path") or "-")

    def _event_reason(self, event: dict) -> str:
        return str(event.get("reason") or "-")

    def _parse_ts(self, value: str) -> datetime:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _monitor_path_matches_policy_blocklist(raw: str, pol: dict) -> bool:
        """True wenn Anzeige-Pfad wie Policy-blockierte Dateinamen aussieht (Screenshot-Schutz)."""
        if not raw or raw == "-":
            return False
        blocked = pol.get("blocked") if isinstance(pol.get("blocked"), dict) else {}
        name = Path(raw).name.lower()
        ps = Path(raw).suffix.lower()
        suffixes = {str(x).strip().lower() for x in blocked.get("suffixes", []) if str(x).strip()}
        for pat in suffixes:
            if any(c in pat for c in "*?["):
                if fnmatch.fnmatch(name, pat):
                    return True
            else:
                if name.endswith(pat) or ps == pat:
                    return True
        nt = blocked.get("name_contains", [])
        if isinstance(nt, list):
            for tok in nt:
                t = str(tok).lower()
                if t and t in name:
                    return True
        return False

    def _format_path_for_monitor(self, raw: str, pol: dict | None = None) -> str:
        s = raw or "-"
        if self._mon_show_full_paths.get():
            return s
        if pol is not None and s not in ("-", "") and self._monitor_path_matches_policy_blocklist(s, pol):
            p = Path(s)
            parent = str(p.parent)
            if len(parent) > 40:
                parent = parent[:14] + "…" + parent[-20:]
            suf = (p.suffix or "").lower()
            return f"{parent}\\***sensitiv***{suf}" if suf else f"{parent}\\***sensitiv***"
        if len(s) <= 48:
            return s
        return s[:18] + "…" + s[-22:]

    def _mon_ts_within_window(self, ts_raw: str) -> bool:
        mins = int(self._mon_time_minutes.get() or 0)
        if mins <= 0:
            return True
        try:
            dt = self._parse_ts(str(ts_raw))
            age_m = (datetime.now(timezone.utc) - dt).total_seconds() / 60.0
            return age_m <= float(mins)
        except Exception:
            return True

    def _mon_event_visible(self, event: dict) -> bool:
        if not self._mon_ts_within_window(str(event.get("ts", ""))):
            return False
        tool_f = (self._mon_filter_tool.get() or "").strip().lower()
        if tool_f and tool_f not in str(event.get("tool", "")).lower():
            return False
        out_f = (self._mon_filter_outcome.get() or "alle").strip().lower()
        if out_f and out_f != "alle":
            evo = str(event.get("outcome", "")).strip().lower()
            if out_f == "ok" and evo == "denied":
                return False
            if out_f == "denied" and evo != "denied":
                return False
        q = (self._mon_filter_search.get() or "").strip().lower()
        if q:
            blob = " ".join(
                str(event.get(k, ""))
                for k in ("ts", "outcome", "tool", "reason", "client_name", "client_id")
            )
            blob += " " + self._event_client(event) + " " + self._event_ip(event)
            blob += " " + self._event_path(event) + " " + self._event_ua(event)
            if q not in blob.lower():
                return False
        return True

    def analyze_behavior(self, events: list[dict]) -> list[dict]:
        """Layer-2-Heuristik nur aus Meta (Client, UA, Rate, Outcome) — kein Pfad-Scoring (BUG-025)."""
        per_minute = {}
        for event in events:
            key = (self._event_client(event), self._parse_ts(str(event.get("ts", ""))).strftime("%Y-%m-%d %H:%M"))
            per_minute[key] = per_minute.get(key, 0) + 1

        flagged = []
        for event in events:
            score = 0
            flags = []

            outcome = str(event.get("outcome", ""))
            client = self._event_client(event)
            ua = self._event_ua(event)
            key = (client, self._parse_ts(str(event.get("ts", ""))).strftime("%Y-%m-%d %H:%M"))
            rpm = per_minute.get(key, 0)

            if outcome == "denied":
                score += 45
                flags.append("denied")
            if "(kein client_id)" in client:
                score += 20
                flags.append("missing_client_id")
            if ua == "-":
                score += 10
                flags.append("missing_user_agent")
            if rpm >= 40:
                score += 20
                flags.append(f"high_rate_{rpm}/min")

            if score >= 25:
                e = dict(event)
                e["score"] = score
                e["flags"] = flags
                flagged.append(e)

        return flagged

    def refresh_monitor(self) -> None:
        self.events = self._load_events()
        self.suspicious = self.analyze_behavior(self.events)
        self.last_transfer_stats = self._compute_transfer_stats(self.events)
        pol_view = self._read_policy_file()

        for item in self.all_tree.get_children():
            self.all_tree.delete(item)
        for item in self.sus_tree.get_children():
            self.sus_tree.delete(item)

        tail = self.events[-700:]
        vis_all = [e for e in tail if self._mon_event_visible(e)]
        for event in reversed(vis_all):
            self.all_tree.insert("", tk.END, values=(
                event.get("ts", "-"),
                event.get("outcome", "-"),
                event.get("tool", "-"),
                self._event_client(event),
                self._event_ip(event),
                self._event_country(event),
                self._event_ua(event),
                self._format_path_for_monitor(self._event_path(event), pol_view),
                self._event_reason(event),
            ))

        tail_s = self.suspicious[-700:]
        vis_sus = [e for e in tail_s if self._mon_event_visible(e)]
        for event in reversed(vis_sus):
            score = event.get("score", 0)
            flags = event.get("flags") or []
            flag_txt = ", ".join(str(x) for x in flags) if flags else "—"
            meta = flag_txt if not flags else f"{flag_txt}  (Stufe {score})"
            self.sus_tree.insert("", tk.END, values=(
                event.get("ts", "-"),
                event.get("tool", "-"),
                self._event_client(event),
                self._event_ip(event),
                self._format_path_for_monitor(self._event_path(event), pol_view),
                meta,
            ))

        self.summary_var.set(
            f"Einträge: {len(self.events)} (Anzeige: {len(vis_all)}) | "
            f"Verdächtig: {len(self.suspicious)} (Anzeige: {len(vis_sus)}) | Log: {_today_access_log().name}"
        )
        self.traffic_var.set(
            "Transfer: "
            f"Senden {self._bytes_per_sec_to_str(self.last_transfer_stats['upload_rate'])} "
            f"(gesamt {self._format_bytes(self.last_transfer_stats['upload_total'])}) | "
            f"Empfangen {self._bytes_per_sec_to_str(self.last_transfer_stats['download_rate'])} "
            f"(gesamt {self._format_bytes(self.last_transfer_stats['download_total'])}) | "
            f"Gesamt {self._format_bytes(self.last_transfer_stats['total'])}"
        )
        self.update_tunnel_url()

    def _export_payload(self) -> dict:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "policy_file": str(POLICY_FILE),
            "total_events": len(self.events),
            "suspicious_events": len(self.suspicious),
            "transfer": self.last_transfer_stats,
            "events": self.events,
            "suspicious": self.suspicious,
        }

    def _default_export_path(self, prefix: str, seq: int) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return EXPORT_DIR / f"mcc_access_{seq:06d}_{prefix}_{stamp}.json"

    def export_now(self) -> None:
        self.refresh_monitor()
        seq = self._get_export_sequence()
        target = filedialog.asksaveasfilename(
            title="Export",
            initialdir=str(EXPORT_DIR),
            initialfile=self._default_export_path("manual", seq).name,
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not target:
            return
        Path(target).write_text(json.dumps(self._export_payload(), ensure_ascii=False, indent=2), encoding="utf-8")
        self.status_var.set(f"Status: Export erstellt → {target}")

    def _auto_export(self, prefix: str) -> Path:
        self.refresh_monitor()
        seq = self._get_export_sequence()
        out = self._default_export_path(prefix, seq)
        out.write_text(json.dumps(self._export_payload(), ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    def disconnect_and_export(self) -> None:
        if self._disconnect_called:
            messagebox.showinfo(
                t("app_title"),
                t("disconnect_already"),
                parent=self,
            )
            return
        try:
            out = self._auto_export("disconnect")
            self.stop_stack()
            self._disconnect_called = True
            self._ops(f"Trennen + Export: {out}")
            messagebox.showinfo(
                t("app_title"),
                t("disconnect_ok").format(path=out),
                parent=self,
            )
        except OSError as exc:
            messagebox.showerror(
                "Trennen + Export",
                f"Export oder Schreiben fehlgeschlagen:\n{exc}\n\n"
                f"Zielordner: {EXPORT_DIR}",
                parent=self,
            )
            self._ops(f"FEHLER Trennen+Export: {exc}")
        except Exception as exc:
            messagebox.showerror("Trennen + Export", str(exc), parent=self)
            self._ops(f"FEHLER Trennen+Export: {exc}")

    def build_exe(self) -> None:
        """Nur für lokale Entwicklung; Button ist in der PyInstaller-EXE ausgeblendet."""
        self._ops("Starte EXE-Build ...")
        bat = BASE_DIR / "build_mcc.bat"
        if not bat.is_file():
            bat = BASE_DIR / "scripts" / "build_guardian_app.bat"
        result = subprocess.run(
            ["cmd", "/c", str(bat)],
            cwd=str(BASE_DIR),
            check=False,
            capture_output=True,
            text=True,
        )
        self._ops((result.stdout or "").strip() or "(kein stdout)")
        if result.returncode == 0:
            self._ops(t("build_ok"))
            messagebox.showinfo("Build", t("build_ok"))
        else:
            self._ops(result.stderr or "Build fehlgeschlagen")
            messagebox.showerror("Build", t("build_fail"))

    def _update_live_statusbar(self) -> None:
        if not getattr(self, "uptime_var", None):
            return
        if self.server_proc and self.server_proc.poll() is None and self.server_start_time:
            delta = datetime.now(timezone.utc) - self.server_start_time
            total_s = int(delta.total_seconds())
            h, rem = divmod(total_s, 3600)
            m, s = divmod(rem, 60)
            self.uptime_var.set(f"Uptime: {h:02d}:{m:02d}:{s:02d}")
        else:
            self.uptime_var.set("Uptime: — gestoppt")
        up = int(self.last_transfer_stats.get("upload_total", 0))
        self.upload_session_var.set(f"Upload Session: {self._format_bytes(up)}")
        last_ev = self.events[-1] if self.events else None
        server_up = bool(self.server_proc and self.server_proc.poll() is None)
        try:
            if server_up:
                self._btn_stack_start.state(["disabled"])
                self._btn_stack_stop.state(["!disabled"])
            else:
                self._btn_stack_start.state(["!disabled"])
                self._btn_stack_stop.state(["disabled"])
        except Exception:
            pass
        if not server_up:
            self.activity_label.config(text=t("activity_stopped"), bg="#888888", fg="white")
        else:
            cur_sus = len(self.suspicious)
            prev_sus = getattr(self, "_activity_prev_suspicious_count", 0)
            self._activity_prev_suspicious_count = cur_sus
            if cur_sus > prev_sus:
                self.activity_label.config(text=t("activity_suspicious"), bg="#c62828", fg="white")
            elif last_ev:
                last_ts = self._parse_ts(str(last_ev.get("ts", "")))
                age_s = (datetime.now(timezone.utc) - last_ts).total_seconds()
                lt = str(last_ev.get("tool", ""))
                if age_s < 10 and lt == "write_file":
                    self.activity_label.config(text=t("activity_upload"), bg="#e67e00", fg="white")
                elif age_s < 10:
                    self.activity_label.config(text=t("activity_active"), bg="#1a7abf", fg="white")
                else:
                    self.activity_label.config(text=t("status_idle_healthy"), bg="#2e7d32", fg="white")
            else:
                self.activity_label.config(text=t("status_idle_healthy"), bg="#2e7d32", fg="white")
        self.after(1000, self._update_live_statusbar)

    def _windows_notify(self, title: str, message: str) -> None:
        try:
            fd, ps_path = tempfile.mkstemp(suffix=".ps1", text=True)
            os.close(fd)
            safe_t = title.replace("'", "''")
            safe_m = message.replace("'", "''")
            script = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$n = New-Object System.Windows.Forms.NotifyIcon; "
                "$n.Icon = [System.Drawing.SystemIcons]::Information; "
                "$n.Visible = $true; "
                f"$n.ShowBalloonTip(5000, '{safe_t}', '{safe_m}', "
                "[System.Windows.Forms.ToolTipIcon]::Warning); "
                "Start-Sleep -Seconds 6; $n.Dispose()"
            )
            Path(ps_path).write_text(script, encoding="utf-8-sig")
            subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps_path],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except Exception:
            pass

    def _schedule_health_loop(self) -> None:
        if not self._health_enabled.get():
            self.after(60_000, self._schedule_health_loop)
            return
        threading.Thread(target=self._health_check_and_log, daemon=True).start()
        mins = max(1, int(self._health_interval_min.get() or 5))
        self.after(mins * 60_000, self._schedule_health_loop)

    def _health_check_and_log(self) -> None:
        try:
            detail_rows: list[dict[str, Any]] = []
            port = self.port_var.get().strip() or "8766"
            host = self.host_var.get().strip() or "127.0.0.1"
            ok_port = self._check_port_open(int(port))
            detail_rows.append({"name": "Port", "ok": ok_port, "detail": f"{host}:{port}"})
            ok_pol = POLICY_FILE.exists()
            detail_rows.append({"name": "Policy-Datei", "ok": ok_pol, "detail": "ok" if ok_pol else "fehlt"})
            passed = sum(1 for r in detail_rows if r.get("ok"))
            failed = len(detail_rows) - passed
            rec = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": "health_check",
                "interval_min": int(self._health_interval_min.get() or 5),
                "passed": passed,
                "failed": failed,
                "results": detail_rows,
            }
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            with HEALTH_LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.after(0, lambda r=dict(rec): self._health_mirror_to_ops_ui(r))
            server_up = self.server_proc is not None and self.server_proc.poll() is None
            if failed > 0 and self._toast_health.get() and server_up:
                self.after(
                    0,
                    lambda n=failed: self._windows_notify(
                        t("health_toast_title"),
                        f"{n} Prüfung(en) fehlgeschlagen",
                    ),
                )
        except Exception:
            pass

    def _schedule_timeout_loop(self) -> None:
        if not self._timeout_enabled.get():
            self.after(60_000, self._schedule_timeout_loop)
            return
        now = datetime.now(timezone.utc)
        if not self.events:
            self.after(60_000, self._schedule_timeout_loop)
            return
        last_ts = self._parse_ts(str(self.events[-1].get("ts", "")))
        idle_min = (now - last_ts).total_seconds() / 60.0
        limit = max(1, int(self._timeout_minutes.get() or 60))
        if idle_min >= limit - 2 and idle_min < limit and not self._timeout_warned and self._toast_timeout_warn.get():
            self._timeout_warned = True
            self._windows_notify(t("app_title"), "Server wird in 2 Minuten gestoppt (Inaktivität).")
        if idle_min >= limit and self.server_proc and self.server_proc.poll() is None:
            self.after(0, self.stop_stack)
            self._timeout_warned = False
        self.after(60_000, self._schedule_timeout_loop)

    def _auto_refresh(self) -> None:
        self.refresh_monitor()
        sus = len(self.suspicious)
        if sus > self._last_suspicious_count and self._toast_suspicious.get():
            self._windows_notify(t("app_title"), t("toast_suspicious"))
        self._last_suspicious_count = sus
        self.after(3000, self._auto_refresh)

    def _on_close(self) -> None:
        self._save_guardian_ui_settings()
        if not self._disconnect_called:
            out = self._auto_export("shutdown")
            self.stop_stack()
            self._ops(f"Auto-Export bei Beenden: {out}")
        self.destroy()


if __name__ == "__main__":
    app = GuardianControlCenter()
    if getattr(app, "_app_ready", False):
        app.mainloop()
