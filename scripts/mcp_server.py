import base64
import fnmatch
import hashlib
import json
import os
import secrets
import shutil
import time
import uuid
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional

import sys as _sys
import ctypes

from fastmcp import Context, FastMCP
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.auth.providers.google import GoogleProvider


def _mcc_home() -> Path:
    return Path(os.environ.get("MCC_HOME", str(Path.home() / ".mcc"))).expanduser().resolve()


def _resolve_policy_path() -> Path:
    raw = (os.getenv("MCP_POLICY_FILE") or os.getenv("MCC_POLICY_PATH") or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (_mcc_home() / "config" / "mcp_policy.json").resolve()


def _resolve_config_dir() -> Path:
    return _resolve_policy_path().parent


def _resolve_log_dir() -> Path:
    raw = (os.getenv("MCC_LOG_DIR") or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (_mcc_home() / "logs").resolve()


CONFIG_DIR = _resolve_config_dir()
LOG_DIR = _resolve_log_dir()
DEFAULT_POLICY_PATH = _resolve_policy_path()
KEYSTORE_PATH = CONFIG_DIR / "keystore.enc"
KEYSTORE_SALT_PATH = CONFIG_DIR / "keystore.salt"
RATE_STATE_PATH = CONFIG_DIR / "rate_state.json"
SESSION_ID = uuid.uuid4().hex

def _load_startup_secrets() -> dict[str, Any]:
    """OAuth/Bearer-Startwerte: zuerst ``MCP_SECRETS_FILE`` (MCC), sonst stdin (Legacy)."""
    path = (os.getenv("MCP_SECRETS_FILE") or "").strip()
    if path:
        p = Path(path)
        try:
            if p.is_file():
                raw = p.read_text(encoding="utf-8")
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
                if raw.strip():
                    try:
                        loaded = json.loads(raw)
                        if isinstance(loaded, dict):
                            return loaded
                    except json.JSONDecodeError as exc:
                        print(f"MCC MCP: JSON in MCP_SECRETS_FILE invalid: {exc}", file=_sys.stderr)
        except OSError as exc:
            print(f"MCC MCP: MCP_SECRETS_FILE could not be read: {exc}", file=_sys.stderr)
        return {}
    try:
        if _sys.stdin is None or _sys.stdin.isatty():
            return {}
        raw = _sys.stdin.read()
        if not raw.strip():
            return {}
        try:
            loaded = json.loads(raw)
            return loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError as exc:
            print(f"MCC MCP: JSON from stdin invalid: {exc}", file=_sys.stderr)
            return {}
    except Exception as exc:
        print(f"MCC MCP: stdin read failed: {exc}", file=_sys.stderr)
        return {}


_STARTUP_SECRETS: dict[str, Any] = _load_startup_secrets()

# Deny-Reason-Kategorien (Monitoring / Auswertung)
DENY_AUTH = "AUTH_FAIL"
DENY_RATE = "RATE_LIMIT"
DENY_POLICY = "POLICY_DENY"
DENY_TECH = "TECH_ERROR"

MAX_WRITE_BYTES = 5_000_000


def _access_log_path() -> Path:
    """Tägliche Rotation: mcp_access_YYYYMMDD.jsonl"""
    return LOG_DIR / f"mcp_access_{date.today().strftime('%Y%m%d')}.jsonl"


DEFAULT_POLICY: dict[str, Any] = {
    "roots": [],
    "permissions": {
        "mode": "read_only",
        "write_allow_paths": [],
        "write_deny_paths": [],
    },
    "blocked": {
        "dir_names": [
            ".git",
            ".svn",
            ".hg",
            ".idea",
            ".vscode",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "$recycle.bin",
            "system volume information",
            "windows",
            "programdata",
        ],
        "path_parts": [
            "appdata",
            ".ssh",
            ".gnupg",
            ".aws",
            ".azure",
            ".kube",
            ".docker",
            ".config",
        ],
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
        "file_names": [
            "id_rsa",
            "id_ed25519",
            "authorized_keys",
            "known_hosts",
            "credentials",
            "config.json",
        ],
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
    # honeypot section intentionally absent from DEFAULT_POLICY
    # (only active when explicitly set in mcp_policy.json)
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_path(path: str) -> str:
    return str(Path(path)).replace("\\", "/").lower().rstrip("/")


def _deep_merge(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in incoming.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _ensure_default_policy(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    path.write_text(json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_policy() -> dict[str, Any]:
    policy_path = _resolve_policy_path()
    _ensure_default_policy(policy_path)

    try:
        custom = json.loads(policy_path.read_text(encoding="utf-8"))
        if not isinstance(custom, dict):
            custom = {}
    except Exception:
        custom = {}

    merged = _deep_merge(DEFAULT_POLICY, custom)
    merged["_policy_path"] = str(policy_path)
    return merged


def _get_policy() -> dict[str, Any]:
    """Lädt Policy bei jedem Aufruf frisch (kein Restart nötig bei JSON-Änderungen)."""
    return _load_policy()


# ── Policy-Integrität (SHA256 der Policy-Datei, Referenz beim ersten MCP-Request) ──
_POLICY_INTEGRITY_BASELINE_HEX: str | None = None
_POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC: str | None = None
_POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT: str | None = None
_POLICY_INTEGRITY_LAST_VERIFY_MONO: float | None = None
_POLICY_INTEGRITY_STARTUP_VERIFIED: bool = False
_POLICY_INTEGRITY_STARTUP_AT_UTC: str | None = None
_POLICY_INTEGRITY_STARTUP_ERROR: str = ""

_INTEGRITY_TOOL_CATEGORY: dict[str, str] = {
    "write_file": "write",
    "create_directory": "write",
    "delete_path": "write",
    "read_file": "read",
    "list_directory": "read",
    "search_files": "read",
    "list_roots": "read",
    "policy_snapshot": "read",
}


def _policy_path_resolved() -> Path:
    return _resolve_policy_path()


def _policy_integrity_config(pol: dict[str, Any]) -> dict[str, Any]:
    adv = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    pi = adv.get("policy_integrity")
    if not isinstance(pi, dict):
        return {
            "enabled": True,
            "scope": "selective",
            "categories": ["write", "exec"],
            "interval_minutes": 5,
            "include_keystore_files": True,
        }
    scope_raw = pi.get("scope")
    scope = scope_raw if scope_raw in ("all", "selective", "all_interval") else "selective"
    try:
        interval_minutes = int(pi.get("interval_minutes", 0))
    except (TypeError, ValueError):
        interval_minutes = 0
    if scope == "all_interval" and interval_minutes < 1:
        interval_minutes = 5
    out = {
        "enabled": bool(pi.get("enabled", True)),
        "scope": scope,
        "categories": pi.get("categories") if isinstance(pi.get("categories"), list) else ["write", "exec"],
        "interval_minutes": interval_minutes,
        "include_keystore_files": bool(pi.get("include_keystore_files", True)),
    }
    if not out["categories"]:
        out["categories"] = ["write", "exec"]
    return out


def _sha256_file_or_empty(path: Path) -> str:
    """SHA256 der Rohbytes; fehlende Datei → leerer String (fester Sentinel)."""
    try:
        if path.is_file():
            return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    return ""


def _ensure_keystore_integrity_baseline_lazy(cfg: dict[str, Any]) -> None:
    """Setzt Keystore-/Salt-Baseline beim ersten Check, falls Policy zuvor ohne Keystore-Scope startete."""
    global _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC, _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT
    if not cfg.get("include_keystore_files", True):
        return
    if _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC is not None:
        return
    _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC = _sha256_file_or_empty(KEYSTORE_PATH)
    _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT = _sha256_file_or_empty(KEYSTORE_SALT_PATH)


def _ensure_policy_integrity_baseline(pol: dict[str, Any]) -> None:
    global _POLICY_INTEGRITY_BASELINE_HEX
    global _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC, _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT
    cfg = _policy_integrity_config(pol)
    if not cfg.get("enabled", True):
        return
    if _POLICY_INTEGRITY_BASELINE_HEX is not None:
        return
    path = _policy_path_resolved()
    try:
        _POLICY_INTEGRITY_BASELINE_HEX = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    if cfg.get("include_keystore_files", True):
        _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC = _sha256_file_or_empty(KEYSTORE_PATH)
        _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT = _sha256_file_or_empty(KEYSTORE_SALT_PATH)
    else:
        _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC = None
        _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT = None


def _policy_integrity_applies_to_tool(tool: str, cfg: dict[str, Any]) -> bool:
    if cfg.get("scope") in ("all", "all_interval"):
        return True
    cat = _INTEGRITY_TOOL_CATEGORY.get(tool, "other")
    categories = {str(c).lower() for c in (cfg.get("categories") or [])}
    if cat == "other":
        return "other" in categories
    return cat in categories


def _check_policy_integrity_or_deny(
    tool: str,
    pol: dict[str, Any],
    ctx: Context | None,
    args: dict,
) -> None:
    global _POLICY_INTEGRITY_LAST_VERIFY_MONO
    cfg = _policy_integrity_config(pol)
    if not cfg.get("enabled", True):
        return
    _ensure_policy_integrity_baseline(pol)
    if _POLICY_INTEGRITY_BASELINE_HEX is None:
        return
    if not _policy_integrity_applies_to_tool(tool, cfg):
        return
    if cfg.get("scope") == "all_interval":
        try:
            interval_min = int(cfg.get("interval_minutes") or 5)
        except (TypeError, ValueError):
            interval_min = 5
        if interval_min < 1:
            interval_min = 1
        if _POLICY_INTEGRITY_LAST_VERIFY_MONO is not None:
            if (time.monotonic() - _POLICY_INTEGRITY_LAST_VERIFY_MONO) < interval_min * 60:
                return
    path = _policy_path_resolved()
    try:
        current = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        _deny(
            tool,
            f"Policy file not readable: {exc}",
            args,
            ctx,
            deny_detail="policy_integrity_read_error",
        )
    if current != _POLICY_INTEGRITY_BASELINE_HEX:
        _deny(
            tool,
            "Policy file changed since server start (SHA256 integrity). Please restart MCP.",
            args,
            ctx,
            deny_detail="policy_integrity_mismatch",
        )
    if cfg.get("include_keystore_files", True):
        _ensure_keystore_integrity_baseline_lazy(cfg)
        try:
            cur_enc = (
                hashlib.sha256(KEYSTORE_PATH.read_bytes()).hexdigest()
                if KEYSTORE_PATH.is_file()
                else ""
            )
        except OSError as exc:
            _deny(
                tool,
                f"Keystore file not readable: {exc}",
                args,
                ctx,
                deny_detail="policy_integrity_keystore_read_error",
            )
        try:
            cur_salt = (
                hashlib.sha256(KEYSTORE_SALT_PATH.read_bytes()).hexdigest()
                if KEYSTORE_SALT_PATH.is_file()
                else ""
            )
        except OSError as exc:
            _deny(
                tool,
                f"Keystore salt file not readable: {exc}",
                args,
                ctx,
                deny_detail="policy_integrity_salt_read_error",
            )
        if cur_enc != _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC or cur_salt != _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT:
            _deny(
                tool,
                "Keystore or salt changed since reference snapshot (SHA256). Please restart MCP.",
                args,
                ctx,
                deny_detail="policy_integrity_keystore_mismatch",
            )
    if cfg.get("scope") == "all_interval":
        _POLICY_INTEGRITY_LAST_VERIFY_MONO = time.monotonic()


def _write_policy_integrity_startup_marker(payload: dict[str, Any]) -> None:
    """Persistenter Nachweis für MCC-Selbsttest (Punkt 17): Startup-Hashes."""
    try:
        out = CONFIG_DIR / "policy_integrity_startup.json"
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def _policy_integrity_startup_primary() -> None:
    """Vor mcp.run(): Baseline setzen und SHA256 sofort zweimal gegenlesen (Primärprüfung)."""
    global _POLICY_INTEGRITY_BASELINE_HEX
    global _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC, _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT
    global _POLICY_INTEGRITY_STARTUP_VERIFIED, _POLICY_INTEGRITY_STARTUP_AT_UTC, _POLICY_INTEGRITY_STARTUP_ERROR

    _POLICY_INTEGRITY_STARTUP_VERIFIED = False
    _POLICY_INTEGRITY_STARTUP_AT_UTC = None
    _POLICY_INTEGRITY_STARTUP_ERROR = ""

    pol = _get_policy()
    cfg = _policy_integrity_config(pol)
    now = datetime.now(timezone.utc).isoformat()

    if not cfg.get("enabled", True):
        _POLICY_INTEGRITY_STARTUP_VERIFIED = True
        _POLICY_INTEGRITY_STARTUP_AT_UTC = now
        _write_policy_integrity_startup_marker(
            {
                "integrity_enabled": False,
                "startup_ok": True,
                "startup_utc": now,
                "message": "policy_integrity disabled in policy",
            }
        )
        print("MCC MCP: Policy integrity disabled -- no SHA256 startup check.", file=_sys.stderr)
        return

    _POLICY_INTEGRITY_BASELINE_HEX = None
    _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC = None
    _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT = None
    _ensure_policy_integrity_baseline(pol)

    if _POLICY_INTEGRITY_BASELINE_HEX is None:
        _POLICY_INTEGRITY_STARTUP_ERROR = "policy_unreadable"
        _write_policy_integrity_startup_marker(
            {
                "integrity_enabled": True,
                "startup_ok": False,
                "startup_utc": now,
                "error": "policy_unreadable",
            }
        )
        print("MCC MCP: Policy integrity: policy file not readable (startup).", file=_sys.stderr)
        return

    path = _policy_path_resolved()
    try:
        second = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        _POLICY_INTEGRITY_STARTUP_ERROR = str(exc)
        _write_policy_integrity_startup_marker(
            {
                "integrity_enabled": True,
                "startup_ok": False,
                "startup_utc": now,
                "error": f"policy_re_read:{exc}",
            }
        )
        print(f"MCC MCP: Policy integrity: primary check read error: {exc}", file=_sys.stderr)
        return

    if second != _POLICY_INTEGRITY_BASELINE_HEX:
        _POLICY_INTEGRITY_STARTUP_ERROR = "policy_hash_primary_mismatch"
        _write_policy_integrity_startup_marker(
            {
                "integrity_enabled": True,
                "startup_ok": False,
                "startup_utc": now,
                "error": "policy_hash_primary_mismatch",
            }
        )
        print("MCC MCP: Policy integrity: primary check HASH mismatch (policy).", file=_sys.stderr)
        return

    if cfg.get("include_keystore_files", True):
        _ensure_keystore_integrity_baseline_lazy(cfg)
        try:
            cur_enc = (
                hashlib.sha256(KEYSTORE_PATH.read_bytes()).hexdigest()
                if KEYSTORE_PATH.is_file()
                else ""
            )
        except OSError as exc:
            _POLICY_INTEGRITY_STARTUP_ERROR = f"keystore_read:{exc}"
            _write_policy_integrity_startup_marker(
                {
                    "integrity_enabled": True,
                    "startup_ok": False,
                    "startup_utc": now,
                    "error": f"keystore_read:{exc}",
                    "policy_sha256": _POLICY_INTEGRITY_BASELINE_HEX,
                }
            )
            print(f"MCC MCP: Policy integrity: keystore primary check: {exc}", file=_sys.stderr)
            return
        try:
            cur_salt = (
                hashlib.sha256(KEYSTORE_SALT_PATH.read_bytes()).hexdigest()
                if KEYSTORE_SALT_PATH.is_file()
                else ""
            )
        except OSError as exc:
            _POLICY_INTEGRITY_STARTUP_ERROR = f"salt_read:{exc}"
            _write_policy_integrity_startup_marker(
                {
                    "integrity_enabled": True,
                    "startup_ok": False,
                    "startup_utc": now,
                    "error": f"salt_read:{exc}",
                    "policy_sha256": _POLICY_INTEGRITY_BASELINE_HEX,
                }
            )
            print(f"MCC MCP: Policy integrity: salt primary check: {exc}", file=_sys.stderr)
            return

        if (
            cur_enc != _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC
            or cur_salt != _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT
        ):
            _POLICY_INTEGRITY_STARTUP_ERROR = "keystore_hash_primary_mismatch"
            _write_policy_integrity_startup_marker(
                {
                    "integrity_enabled": True,
                    "startup_ok": False,
                    "startup_utc": now,
                    "error": "keystore_hash_primary_mismatch",
                    "policy_sha256": _POLICY_INTEGRITY_BASELINE_HEX,
                }
            )
            print("MCC MCP: Policy integrity: primary check HASH mismatch (keystore/salt).", file=_sys.stderr)
            return

    _POLICY_INTEGRITY_STARTUP_VERIFIED = True
    _POLICY_INTEGRITY_STARTUP_AT_UTC = now
    marker: dict[str, Any] = {
        "integrity_enabled": True,
        "include_keystore_files": bool(cfg.get("include_keystore_files", True)),
        "startup_ok": True,
        "startup_utc": now,
        "policy_sha256": _POLICY_INTEGRITY_BASELINE_HEX,
    }
    if cfg.get("include_keystore_files", True):
        marker["keystore_enc_sha256"] = _POLICY_INTEGRITY_BASELINE_KEYSTORE_ENC or ""
        marker["keystore_salt_sha256"] = _POLICY_INTEGRITY_BASELINE_KEYSTORE_SALT or ""
    _write_policy_integrity_startup_marker(marker)
    pfx = _POLICY_INTEGRITY_BASELINE_HEX[:16]
    print(
        f"MCC MCP: Policy integrity startup primary check OK policy_sha256={pfx}…",
        file=_sys.stderr,
    )


def _build_auth_provider():
    mode = (_STARTUP_SECRETS.get("auth_mode") or os.getenv("MCP_AUTH_MODE", "none")).strip().lower()
    if mode in {"", "none", "off", "disabled"}:
        return None

    if mode == "bearer":
        # Auth erfolgt pro Tool über Authorization: Bearer (siehe _run_request_pipeline)
        return None

    base_url = (_STARTUP_SECRETS.get("public_base_url") or os.getenv("MCP_PUBLIC_BASE_URL", "")).strip()
    client_id = (_STARTUP_SECRETS.get("oauth_client_id") or os.getenv("MCP_OAUTH_CLIENT_ID", "")).strip()
    client_secret = (_STARTUP_SECRETS.get("oauth_client_secret") or os.getenv("MCP_OAUTH_CLIENT_SECRET", "")).strip()

    if not base_url:
        raise ValueError("MCP_PUBLIC_BASE_URL missing for OAuth mode")
    if not client_id or not client_secret:
        raise ValueError("MCP_OAUTH_CLIENT_ID/MCP_OAUTH_CLIENT_SECRET missing")

    redirect_path = os.getenv("MCP_OAUTH_REDIRECT_PATH", "/oauth/callback").strip() or "/oauth/callback"
    _sco = _STARTUP_SECRETS.get("oauth_scopes")
    scopes_raw = _sco.strip() if isinstance(_sco, str) else ""
    if not scopes_raw:
        scopes_raw = os.getenv("MCP_OAUTH_SCOPES", "")
    scopes = [part.strip() for part in scopes_raw.split(",") if part.strip()] or None

    if mode == "github":
        return GitHubProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            redirect_path=redirect_path,
            required_scopes=scopes,
        )

    if mode == "google":
        return GoogleProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            redirect_path=redirect_path,
            required_scopes=scopes,
        )

    if mode == "oidc":
        config_url = os.getenv("MCP_OIDC_CONFIG_URL", "").strip()
        if not config_url:
            raise ValueError("MCP_OIDC_CONFIG_URL missing for OIDC mode")

        audience = os.getenv("MCP_OIDC_AUDIENCE", "").strip() or None
        return OIDCProxy(
            config_url=config_url,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            redirect_path=redirect_path,
            required_scopes=scopes,
            audience=audience,
        )

    raise ValueError(f"Unknown MCP_AUTH_MODE: {mode}")


try:
    mcp = FastMCP("MCC", auth=_build_auth_provider())
except Exception as exc:
    import sys as _sys

    print(f"MCC MCP: Initialisation failed: {exc}", file=_sys.stderr)
    raise


def _context_snapshot(ctx: Context | None) -> dict[str, Any]:
    if ctx is None:
        return {}

    out = {
        "client_id": getattr(ctx, "client_id", None),
        "request_id": getattr(ctx, "request_id", None),
        "origin_request_id": getattr(ctx, "origin_request_id", None),
    }

    request_ctx = None
    try:
        request_ctx = ctx.request_context
    except Exception:
        request_ctx = None

    if request_ctx is None:
        return out

    request = getattr(request_ctx, "request", None)
    if request is not None:
        headers = {}
        if hasattr(request, "headers"):
            headers = dict(request.headers)
        out["http"] = {
            "method": getattr(request, "method", None),
            "path": getattr(getattr(request, "url", None), "path", None),
            "client": str(getattr(request, "client", None)),
            "user_agent": headers.get("user-agent"),
            "x_forwarded_for": headers.get("x-forwarded-for"),
            "cf_connecting_ip": headers.get("cf-connecting-ip"),
            "cf_ray": headers.get("cf-ray"),
        }

    return out


def _get_real_ip(ctx: Context | None) -> str:
    """Effektive Client-IP: CF-Connecting-IP, sonst X-Forwarded-For, sonst Request-Client."""
    if ctx is None:
        return "unknown"
    headers: dict[str, str] = {}
    try:
        request_ctx = getattr(ctx, "request_context", None)
        if request_ctx is not None:
            request = getattr(request_ctx, "request", None)
            if request is not None and hasattr(request, "headers"):
                headers = {str(k).lower(): v for k, v in dict(request.headers).items()}
    except Exception:
        pass
    
    cf = headers.get("cf-connecting-ip")
    if not cf:
        cf = headers.get("true-client-ip")
    xff = (headers.get("x-forwarded-for") or "").split(",")[0].strip() or None
    ip = cf or xff
    if not ip:
        try:
            request_ctx = getattr(ctx, "request_context", None)
            if request_ctx is not None:
                request = getattr(request_ctx, "request", None)
                if request is not None:
                    client = getattr(request, "client", None)
                    if client is not None:
                        host = getattr(client, "host", None)
                        if host:
                            ip = str(host)
        except Exception:
            pass
    return ip or "unknown"


def _log_access(
    tool: str,
    args: dict,
    outcome: str,
    ctx: Context | None = None,
    reason: str | None = None,
    *,
    deny_category: str | None = None,
    deny_detail: str | None = None,
    request_id: str | None = None,
    client_name: str | None = None,
) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    rid = request_id
    if not rid and ctx is not None:
        rid = getattr(ctx, "request_id", None)
    if not rid:
        rid = uuid.uuid4().hex[:12]
    event = {
        "ts": _utc_now(),
        "session_id": SESSION_ID,
        "request_id": rid,
        "server_pid": os.getpid(),
        "tool": tool,
        "args": args,
        "outcome": outcome,
        "reason": reason,
        "effective_ip": _get_real_ip(ctx),
    }
    if deny_category:
        event["deny_category"] = deny_category
    if deny_detail:
        event["deny_detail"] = deny_detail
    if client_name:
        event["client_name"] = client_name
    snap = _context_snapshot(ctx)
    if snap.get("request_id") is None:
        snap["request_id"] = rid
    event.update(snap)

    with _access_log_path().open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")


def _json_size_bytes(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
    except Exception:
        return 0


def _deny(
    tool: str,
    reason: str,
    args: dict,
    ctx: Context | None = None,
    *,
    deny_category: str = DENY_POLICY,
    deny_detail: str | None = None,
) -> None:
    _log_access(
        tool,
        args=args,
        outcome="denied",
        reason=reason,
        ctx=ctx,
        deny_category=deny_category,
        deny_detail=deny_detail or reason,
    )
    raise ValueError(reason)


def _roots_from_policy_dict(pol: dict[str, Any]) -> list[Path]:
    roots = pol.get("roots") or []
    if not isinstance(roots, list):
        roots = []

    parsed: list[Path] = []
    for raw in roots:
        if isinstance(raw, str) and raw.strip():
            parsed.append(Path(raw).resolve())
    return parsed


def _blocked_set_from_pol(pol: dict[str, Any], key: str) -> set[str]:
    blocked = pol.get("blocked", {})
    values = blocked.get(key, []) if isinstance(blocked, dict) else []
    if not isinstance(values, list):
        return set()
    return {str(v).lower() for v in values}


def _honeypot_bypass_paths_from_pol(pol: dict[str, Any]) -> list[Path]:
    honeypot = pol.get("honeypot", {})
    if not isinstance(honeypot, dict):
        return []
    raw_list = honeypot.get("bypass_name_filter_paths", [])
    if not isinstance(raw_list, list):
        return []
    result = []
    for raw in raw_list:
        if isinstance(raw, str) and raw.strip():
            result.append(Path(raw).resolve())
    return result


BLOCKED_IPS_PATH = CONFIG_DIR / "blocked_ips.json"
_request_log: dict[str, list[float]] = defaultdict(list)

def _load_rate_state() -> dict[str, int]:
    if RATE_STATE_PATH.exists():
        try:
            data = json.loads(RATE_STATE_PATH.read_text(encoding="utf-8"))
            raw = data.get("auth_failures", {})
            return {str(k): int(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
        except Exception:
            return {}
    return {}

def _save_rate_state() -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        state = {"auth_failures": dict(_auth_failures), "updated": _utc_now()}
        RATE_STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

_auth_failures: dict[str, int] = defaultdict(int, _load_rate_state())


def _load_blocked_ips() -> dict[str, Any]:
    if not BLOCKED_IPS_PATH.exists():
        return {}
    try:
        data = json.loads(BLOCKED_IPS_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _block_ip(ip: str, reason: str) -> None:
    blocked = _load_blocked_ips()
    blocked[ip] = {
        "reason": reason,
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "auto": True,
    }
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    BLOCKED_IPS_PATH.write_text(json.dumps(blocked, indent=2, ensure_ascii=False), encoding="utf-8")


def _check_blocklist(ip: str) -> tuple[bool, str]:
    blocked = _load_blocked_ips()
    if ip in blocked:
        return False, f"ip_blocked_since_{blocked[ip].get('blocked_at', '?')}"
    return True, ""


def _register_auth_failure(ip: str) -> None:
    pol = _get_policy()
    rl = pol.get("rate_limit") if isinstance(pol.get("rate_limit"), dict) else {}
    max_f = int(rl.get("block_after_failures", 5))
    _auth_failures[ip] = _auth_failures.get(ip, 0) + 1
    _save_rate_state()
    if _auth_failures[ip] >= max_f:
        _block_ip(ip, f"auth_failures_{_auth_failures[ip]}")


def _clear_auth_failure(ip: str) -> None:
    if ip in _auth_failures:
        _auth_failures.pop(ip, None)
        _save_rate_state()


def _check_rate_limit(ip: str, pol: dict[str, Any]) -> tuple[bool, str]:
    rl = pol.get("rate_limit") if isinstance(pol.get("rate_limit"), dict) else {}
    limit = int(rl.get("requests_per_minute", 30))
    now = time.time()
    cutoff = now - 60.0
    _request_log[ip] = [t for t in _request_log[ip] if t > cutoff]
    if len(_request_log[ip]) >= limit:
        return False, f"rate_exceeded_{len(_request_log[ip])}_per_min"
    _request_log[ip].append(now)
    return True, ""


def _auth_mode() -> str:
    return (_STARTUP_SECRETS.get("auth_mode") or os.getenv("MCP_AUTH_MODE", "none")).strip().lower()


def _load_bearer_keys() -> dict[str, str]:
    """Bearer keys from stdin secrets or MCP_BEARER_KEY_* env vars."""
    keys: dict[str, str] = {}
    stdin_keys = _STARTUP_SECRETS.get("bearer_keys")
    if isinstance(stdin_keys, dict):
        for name, val in stdin_keys.items():
            v = str(val).strip()
            if v:
                keys[str(name).lower()] = v
        if keys:
            return keys
    prefix = "MCP_BEARER_KEY_"
    plen = len(prefix)
    for k, v in os.environ.items():
        ku = k.upper()
        if not ku.startswith(prefix):
            continue
        name = ku[plen:].lower()
        if not name:
            continue
        val = (v or "").strip()
        if val:
            keys[name] = val
    return keys


def _extract_bearer_token(ctx: Context | None) -> str:
    if ctx is None:
        return ""
    try:
        request_ctx = getattr(ctx, "request_context", None)
        if request_ctx is None:
            return ""
        request = getattr(request_ctx, "request", None)
        if request is None or not hasattr(request, "headers"):
            return ""
        headers = dict(request.headers)
        auth = headers.get("authorization") or headers.get("Authorization") or ""
        if not auth.lower().startswith("bearer "):
            return ""
        return auth[7:].strip()
    except Exception:
        return ""


def _get_user_agent(ctx: Context | None) -> str:
    if ctx is None:
        return ""
    try:
        request_ctx = getattr(ctx, "request_context", None)
        if request_ctx is None:
            return ""
        request = getattr(request_ctx, "request", None)
        if request is None or not hasattr(request, "headers"):
            return ""
        headers = dict(request.headers)
        return str(headers.get("user-agent") or headers.get("User-Agent") or "")
    except Exception:
        return ""


def _check_bearer(ctx: Context | None) -> tuple[bool, str]:
    if _auth_mode() != "bearer":
        return True, ""
    keys = _load_bearer_keys()
    if not keys:
        return False, ""
    token = _extract_bearer_token(ctx)
    if not token:
        return False, ""
    for client_name, stored_key in keys.items():
        if secrets.compare_digest(token, stored_key):
            return True, client_name
    return False, ""


def _check_client_blocklist(client_name: str, user_agent: str, pol: dict[str, Any]) -> tuple[bool, str]:
    cb = pol.get("client_blocklist")
    if not isinstance(cb, dict):
        return True, ""
    names = cb.get("blocked_client_names") or []
    subs = cb.get("blocked_user_agent_substrings") or []
    if isinstance(names, list) and client_name and client_name.lower() in {str(n).lower() for n in names}:
        return False, "client_name_blocked"
    ua = user_agent.lower()
    if isinstance(subs, list):
        for s in subs:
            if s and str(s).lower() in ua:
                return False, f"user_agent_blocked:{s}"
    return True, ""


def _run_request_pipeline(ctx: Context | None, tool: str, args: dict) -> str:
    """Blocklist → Rate-Limit → Bearer → Client-Blocklist. Gibt client_name bei Bearer zurück."""
    pol = _get_policy()
    _check_policy_integrity_or_deny(tool, pol, ctx, args)
    ip = _get_real_ip(ctx)

    ok_bl, bl_detail = _check_blocklist(ip)
    if not ok_bl:
        _deny(tool, "IP is blocked", args, ctx, deny_category=DENY_AUTH, deny_detail=bl_detail)

    ok_rl, rl_detail = _check_rate_limit(ip, pol)
    if not ok_rl:
        _deny(tool, rl_detail or "Too many requests", args, ctx, deny_category=DENY_RATE, deny_detail=rl_detail)

    client_name = ""
    if _auth_mode() == "bearer":
        ok_b, cn = _check_bearer(ctx)
        if not ok_b:
            _register_auth_failure(ip)
            _deny(tool, "Unauthorized", args, ctx, deny_category=DENY_AUTH, deny_detail="bearer_invalid")
        _clear_auth_failure(ip)
        client_name = cn
        ua = _get_user_agent(ctx)
        ok_cb, cb_detail = _check_client_blocklist(cn, ua, pol)
        if not ok_cb:
            _deny(tool, "Client is blocked", args, ctx, deny_category=DENY_AUTH, deny_detail=cb_detail)
    return client_name


def _is_under_allowed_root(path: Path, allowed_roots: list[Path]) -> bool:
    resolved = path.resolve()
    for root in allowed_roots:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def _normalized_parts(path: Path) -> list[str]:
    return [part.lower() for part in path.parts]


def _is_blocked_path(path: Path, pol: dict[str, Any]) -> bool:
    dir_names = _blocked_set_from_pol(pol, "dir_names")
    path_parts = _blocked_set_from_pol(pol, "path_parts")
    parts = _normalized_parts(path)
    for part in parts:
        if part in dir_names:
            return True
        if part in path_parts:
            return True
    return False


def _is_in_honeypot_zone(path: Path, pol: dict[str, Any]) -> bool:
    """Prüft ob ein Pfad in einer konfigurierten Honeypot-Bypass-Zone liegt."""
    resolved = path.resolve()
    for bypass_root in _honeypot_bypass_paths_from_pol(pol):
        try:
            resolved.relative_to(bypass_root)
            return True
        except ValueError:
            continue
    return False


# Layer 1: zusätzliche Pfad-Substring-Regeln (ehemals GUI-Scoring; keine Duplikation in Layer 2).
_LAYER1_PATH_SUBSTRING_DENY: tuple[str, ...] = (
    "windows",
    "programdata",
    "appdata",
    ".ssh",
    ".env",
    "secret",
    "token",
    "password",
)


def _suffix_matches_policy(name_lower: str, path_suffix_lower: str, blocked_suffixes: set[str]) -> bool:
    """Literal suffix (endswith / Path.suffix) oder Glob mit fnmatch auf dem Dateinamen (z. B. ``.env.*``)."""
    ps = path_suffix_lower or ""
    for raw in blocked_suffixes:
        pat = str(raw).strip().lower()
        if not pat:
            continue
        if any(c in pat for c in "*?["):
            if fnmatch.fnmatch(name_lower, pat):
                return True
        else:
            if name_lower.endswith(pat) or ps == pat:
                return True
    return False


def _is_blocked_file(path: Path, pol: dict[str, Any]) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    blocked_suffixes = _blocked_set_from_pol(pol, "suffixes")
    blocked_file_names = _blocked_set_from_pol(pol, "file_names")
    blocked_name_contains = _blocked_set_from_pol(pol, "name_contains")

    if _suffix_matches_policy(name, suffix, blocked_suffixes):
        return True
    if name in blocked_file_names:
        return True

    if _is_in_honeypot_zone(path, pol):
        return False

    if any(token in name for token in blocked_name_contains):
        return True

    path_lower = str(path).lower().replace("\\", "/")
    if any(tok in path_lower for tok in _LAYER1_PATH_SUBSTRING_DENY):
        return True

    return False


def _get_long_path_name(short_path: str) -> str:
    if os.name != "nt":
        return short_path
    try:
        buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.kernel32.GetLongPathNameW(short_path, buf, 512)
        return buf.value or short_path
    except Exception:
        return short_path


def _resolve_user_path(user_path: str, pol: dict[str, Any]) -> Path:
    raw = user_path.strip()
    if not raw:
        raw = "."

    adv = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    normalize = adv.get("path_normalization_enabled", True)

    if normalize:
        if "::" in raw or raw.count(":") > 1:
            raise ValueError("Alternate Data Streams not allowed")
        if raw.startswith("\\\\"):
            raise ValueError("UNC paths not allowed")

    allowed_roots = _roots_from_policy_dict(pol)
    if not allowed_roots:
        raise ValueError("No roots configured -- please set at least one root in the policy.")
    candidate = Path(raw)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (allowed_roots[0] / candidate).resolve()

    if normalize:
        resolved = Path(_get_long_path_name(str(resolved)))

    if not _is_under_allowed_root(resolved, allowed_roots):
        raise ValueError("Path not allowed")
    if _is_blocked_path(resolved, pol):
        raise ValueError("Path blocked by policy")
    return resolved


def _write_mode(pol: dict[str, Any]) -> str:
    permissions = pol.get("permissions", {})
    mode = permissions.get("mode", "read_only") if isinstance(permissions, dict) else "read_only"
    return str(mode).lower()


def _path_matches_prefixes(path: Path, prefixes: list[str]) -> bool:
    target = _normalize_path(str(path))
    for prefix in prefixes:
        pref = _normalize_path(prefix)
        if not pref:
            continue
        if target.startswith(pref):
            return True
    return False


def _write_allowed(path: Path, pol: dict[str, Any], client_name: str = "") -> tuple[bool, str | None]:
    if _write_mode(pol) != "read_write":
        return False, "Server is in read_only mode"

    permissions = pol.get("permissions", {})
    if not isinstance(permissions, dict):
        return False, "Invalid permissions configuration"

    deny_paths = permissions.get("write_deny_paths", [])
    if not isinstance(deny_paths, list):
        deny_paths = []

    if deny_paths and _path_matches_prefixes(path, [str(v) for v in deny_paths]):
        return False, "Path is in write_deny_paths"

    agents = permissions.get("agents")
    if isinstance(agents, dict) and client_name:
        entry = agents.get(client_name)
        if isinstance(entry, dict):
            agent_paths = entry.get("write_allow_paths", [])
            if not isinstance(agent_paths, list):
                agent_paths = []
            if not agent_paths:
                return False, f"agent_{client_name}_no_write_paths"
            for p in agent_paths:
                if str(path).startswith(str(p)):
                    return True, None
            return False, f"agent_{client_name}_path_not_allowed"

    allow_paths = permissions.get("write_allow_paths", [])
    if not isinstance(allow_paths, list):
        allow_paths = []

    if not allow_paths:
        return False, "No write_allow_paths configured"
    if not _path_matches_prefixes(path, [str(v) for v in allow_paths]):
        return False, "Path not in write_allow_paths"

    return True, None


def _permissions_snapshot(pol: dict[str, Any]) -> dict[str, Any]:
    """Lesbare Schreib-/Lese-Konfiguration für policy_snapshot (keine Geheimnisse)."""
    p = pol.get("permissions")
    if not isinstance(p, dict):
        return {"mode": "read_only", "write_allow_paths": [], "write_deny_paths": []}
    out: dict[str, Any] = {
        "mode": str(p.get("mode", "read_only")).lower(),
        "write_allow_paths": [str(x).strip() for x in (p.get("write_allow_paths") or []) if str(x).strip()],
        "write_deny_paths": [str(x).strip() for x in (p.get("write_deny_paths") or []) if str(x).strip()],
    }
    agents = p.get("agents")
    if isinstance(agents, dict) and agents:
        ag_out: dict[str, Any] = {}
        for name, entry in agents.items():
            if isinstance(entry, dict):
                wap = entry.get("write_allow_paths", [])
                paths = (
                    [str(x).strip() for x in wap if str(x).strip()]
                    if isinstance(wap, list)
                    else []
                )
                ag_out[str(name)] = {"write_allow_paths": paths}
            else:
                ag_out[str(name)] = {"write_allow_paths": []}
        out["agents"] = ag_out
    return out


def _tool_registry_snapshot(pol: dict[str, Any]) -> dict[str, Any]:
    tr = pol.get("tool_registry")
    if not isinstance(tr, dict):
        return {"active_profile": "standard", "disabled_tools": [], "custom_profiles": {}}
    dt = tr.get("disabled_tools")
    disabled = [str(x) for x in dt] if isinstance(dt, list) else []
    cp_raw = tr.get("custom_profiles")
    cp_out: dict[str, Any] = {}
    if isinstance(cp_raw, dict):
        for k, v in cp_raw.items():
            if isinstance(v, dict) and isinstance(v.get("disabled_tools"), list):
                cp_out[str(k)] = {
                    "disabled_tools": [str(x) for x in v["disabled_tools"] if str(x).strip()],
                }
    return {
        "active_profile": str(tr.get("active_profile", "standard")),
        "disabled_tools": disabled,
        "custom_profiles": cp_out,
    }


def _rate_limit_snapshot(pol: dict[str, Any]) -> dict[str, Any]:
    rl = pol.get("rate_limit")
    if not isinstance(rl, dict):
        return {}
    out: dict[str, Any] = {}
    try:
        out["requests_per_minute"] = int(rl.get("requests_per_minute", 30))
    except (TypeError, ValueError):
        out["requests_per_minute"] = 30
    try:
        out["block_after_failures"] = int(rl.get("block_after_failures", 5))
    except (TypeError, ValueError):
        out["block_after_failures"] = 5
    return out


def _policy_integrity_public_snapshot(pol: dict[str, Any]) -> dict[str, Any]:
    adv = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    pi = adv.get("policy_integrity")
    if not isinstance(pi, dict):
        return {}
    scope = pi.get("scope", "selective")
    if scope not in ("all", "selective", "all_interval"):
        scope = "selective"
    try:
        interval_minutes = int(pi.get("interval_minutes", 0))
    except (TypeError, ValueError):
        interval_minutes = 0
    return {
        "enabled": bool(pi.get("enabled", True)),
        "scope": scope,
        "interval_minutes": interval_minutes,
        "include_keystore_files": bool(pi.get("include_keystore_files", True)),
    }


def _mcp_tools_catalog() -> list[dict[str, Any]]:
    """Statischer Katalog der registrierten Tools inkl. Hinweise (Ordner vs. Datei, Env-Gates)."""
    return [
        {
            "name": "policy_snapshot",
            "category": "read",
            "notes": "Diese Übersicht; kein Zugriff auf Dateien.",
        },
        {"name": "list_roots", "category": "read", "notes": "Nur Roots, die auf dem Host existieren."},
        {
            "name": "list_directory",
            "category": "read",
            "notes": "Ordner auflisten. Für Verzeichnisse verwenden, nicht read_file.",
        },
        {
            "name": "read_file",
            "category": "read",
            "notes": "Nur normale Dateien; bei einem Ordnerpfad schlägt die Prüfung fehl (Keine Datei).",
        },
        {
            "name": "search_files",
            "category": "read",
            "notes": "Optional base_path: Suche nur unter diesem Ordner (muss unter einem Root liegen).",
        },
        {
            "name": "write_file",
            "category": "write",
            "notes": "Benötigt mode read_write und Ziel unter write_allow_paths.",
        },
        {
            "name": "create_directory",
            "category": "write",
            "notes": "Benötigt mode read_write und Ziel unter write_allow_paths.",
        },
        {
            "name": "delete_path",
            "category": "write",
            "notes": "Benötigt mode read_write und Ziel unter write_allow_paths.",
        },
    ]


@mcp.tool()
def policy_snapshot(ctx: Context | None = None) -> dict[str, Any]:
    args: dict[str, Any] = {}
    client_name = _run_request_pipeline(ctx, "policy_snapshot", args)
    pol = _get_policy()
    roots = _roots_from_policy_dict(pol)
    adv = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    try:
        max_write_bytes = int(adv.get("max_write_bytes", MAX_WRITE_BYTES))
    except (TypeError, ValueError):
        max_write_bytes = MAX_WRITE_BYTES
    perms = _permissions_snapshot(pol)
    wap = list(perms.get("write_allow_paths") or [])
    wdp = list(perms.get("write_deny_paths") or [])
    snapshot = {
        "snapshot_version": 3,
        "policy_path": pol.get("_policy_path"),
        "auth_mode": _auth_mode(),
        "bearer_client_name": client_name or None,
        "roots": [str(r) for r in roots],
        "roots_note": "Read/list/search only under these roots (except blocked names/parts).",
        "mode": _write_mode(pol),
        # Explizit auf Top-Level: viele Clients/Assistenten erwarten diese Keys flach (nicht nur unter permissions).
        "write_allow_paths": wap,
        "write_deny_paths": wdp,
        "permissions": perms,
        "permissions_note": (
            "Writing only in mode read_write and when the target path is under write_allow_paths "
            "(also check write_deny_paths as needed). Same lists are also available at the top-level write_*."
        ),
        "blocked": {
            "dir_names": sorted(_blocked_set_from_pol(pol, "dir_names")),
            "path_parts": sorted(_blocked_set_from_pol(pol, "path_parts")),
            "suffixes": sorted(_blocked_set_from_pol(pol, "suffixes")),
            "file_names": sorted(_blocked_set_from_pol(pol, "file_names")),
            "name_contains": sorted(_blocked_set_from_pol(pol, "name_contains")),
        },
        "honeypot": {
            "bypass_name_filter_paths": [str(p) for p in _honeypot_bypass_paths_from_pol(pol)],
        },
        "rate_limit": _rate_limit_snapshot(pol),
        "tool_registry": _tool_registry_snapshot(pol),
        "tools": _mcp_tools_catalog(),
        "policy_integrity": _policy_integrity_public_snapshot(pol),
        "advanced": {
            "max_write_bytes": max_write_bytes,
            "path_normalization_enabled": bool(adv.get("path_normalization_enabled", True)),
        },
        "usage_hints": [
            "Verzeichnisinhalt: list_directory, nicht read_file auf den Ordnerpfad.",
            "Schreibpfade: write_allow_paths und write_deny_paths sind auf Top-Level und unter permissions identisch.",
            "search_files: optionaler Parameter base_path begrenzt die Suche auf einen Unterbaum.",
        ],
        "integrity_startup": {
            "startup_primary_ok": _POLICY_INTEGRITY_STARTUP_VERIFIED,
            "startup_utc": _POLICY_INTEGRITY_STARTUP_AT_UTC,
            "error": _POLICY_INTEGRITY_STARTUP_ERROR or None,
            "marker_file": str(CONFIG_DIR / "policy_integrity_startup.json"),
            "note": "Vor Listen: SHA256-Baseline beim Prozessstart gesetzt und sofort gegengelesen (Primärprüfung).",
        },
    }
    _log_access(
        "policy_snapshot",
        {"ok": True, "response_bytes": _json_size_bytes(snapshot)},
        "ok",
        ctx,
        client_name=client_name or None,
    )
    return snapshot


@mcp.tool()
def list_roots(ctx: Context | None = None) -> list[str]:
    args: dict[str, Any] = {}
    client_name = _run_request_pipeline(ctx, "list_roots", args)
    pol = _get_policy()
    roots = [str(root) for root in _roots_from_policy_dict(pol) if root.exists()]
    _log_access(
        "list_roots",
        {"roots_count": len(roots), "response_bytes": _json_size_bytes(roots)},
        "ok",
        ctx,
        client_name=client_name or None,
    )
    return roots


@mcp.tool()
def list_directory(path: str = ".", ctx: Context | None = None) -> list[str]:
    tool = "list_directory"
    args = {"path": path}
    client_name = _run_request_pipeline(ctx, tool, args)
    pol = _get_policy()

    try:
        target = _resolve_user_path(path, pol)
    except ValueError as error:
        _deny(tool, str(error), args, ctx)
        return []

    if not target.exists():
        _deny(tool, "Path does not exist", args, ctx)
        return []
    if not target.is_dir():
        _deny(tool, "Not a directory", args, ctx)
        return []

    out: list[str] = []
    for item in target.iterdir():
        if _is_blocked_path(item, pol):
            continue
        if item.is_file() and _is_blocked_file(item, pol):
            continue
        out.append(str(item.resolve()))

    result = sorted(out)
    _log_access(
        tool,
        {"path": str(target), "results": len(result), "response_bytes": _json_size_bytes(result)},
        "ok",
        ctx,
        client_name=client_name or None,
    )
    return result


@mcp.tool()
def search_files(
    query: str,
    limit: int = 100,
    base_path: Optional[str] = None,
    ctx: Context | None = None,
) -> list[str]:
    tool = "search_files"
    args = {"query": query, "limit": limit, "base_path": base_path or ""}
    client_name = _run_request_pipeline(ctx, tool, args)
    pol = _get_policy()
    q = query.strip().lower()
    if not q:
        _deny(tool, "Query must not be empty", args, ctx)
        return []
    if limit < 1:
        _deny(tool, "limit must be >= 1", args, ctx)
        return []

    max_hits = min(limit, 500)
    hits: list[str] = []

    all_roots = _roots_from_policy_dict(pol)
    write_paths = pol.get("permissions", {}).get("write_allow_paths", [])
    if not isinstance(write_paths, list):
        write_paths = []
    wp_resolved = [Path(p).resolve() for p in write_paths if isinstance(p, str) and p.strip()]

    adv = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    do_prioritize = adv.get("search_prioritize_write_paths", True)

    bp = (base_path or "").strip()
    if bp:
        try:
            subtree = _resolve_user_path(bp, pol)
        except ValueError as error:
            _deny(tool, str(error), args, ctx)
            return []
        if not subtree.is_dir():
            _deny(tool, "base_path is not a directory", args, ctx)
            return []
        ordered_roots = [subtree]
        do_prioritize = False
    else:
        priority_roots = []
        other_roots = []
        for r in all_roots:
            is_priority = any(_is_under_allowed_root(wp, [r]) or r == wp for wp in wp_resolved)
            if is_priority:
                priority_roots.append(r)
            else:
                other_roots.append(r)
        ordered_roots = (priority_roots + other_roots) if do_prioritize else all_roots

    for root in ordered_roots:
        if len(hits) >= max_hits:
            break
        if not root.exists():
            continue

        for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda _: None):
            base_dir = Path(dirpath)
            dirnames[:] = [name for name in dirnames if not _is_blocked_path(base_dir / name, pol)]

            if _is_blocked_path(base_dir, pol):
                continue

            for filename in filenames:
                candidate = base_dir / filename
                if _is_blocked_file(candidate, pol):
                    continue
                haystack = str(candidate).lower()
                if q in haystack:
                    hits.append(str(candidate))
                    if len(hits) >= max_hits:
                        _log_access(
                            tool,
                            {
                                "query": query,
                                "limit": limit,
                                "results": len(hits),
                                "truncated": True,
                                "prioritized": do_prioritize,
                                "response_bytes": _json_size_bytes(hits),
                            },
                            "ok",
                            ctx,
                            client_name=client_name or None,
                        )
                        return hits

    _log_access(
        tool,
        {"query": query, "limit": limit, "results": len(hits), "truncated": False, "prioritized": do_prioritize, "response_bytes": _json_size_bytes(hits)},
        "ok",
        ctx,
        client_name=client_name or None,
    )
    return hits


@mcp.tool()
def read_file(path: str, max_bytes: int = 200000, ctx: Context | None = None) -> str:
    tool = "read_file"
    args = {"path": path, "max_bytes": max_bytes}
    client_name = _run_request_pipeline(ctx, tool, args)
    pol = _get_policy()

    try:
        target = _resolve_user_path(path, pol)
    except ValueError as error:
        _deny(tool, str(error), args, ctx)
        return ""

    # BUG-011: Blockliste (_is_blocked_file) vor jeder weiteren Prüfung,
    # damit Existenz-Status der Datei nicht durch unterschiedliche Fehlermeldungen leakt.
    if _is_blocked_file(target, pol):
        _deny(tool, "File blocked by policy", args, ctx)
        return ""

    if not target.is_file():
        _deny(tool, "Not a file", args, ctx)
        return ""

    try:
        with target.open("rb") as fh:
            max_len = 2000 if max_bytes < 2000 else min(max_bytes, 2_000_000)
            data = fh.read(max_len)
    except FileNotFoundError:
        _deny(tool, "File does not exist", args, ctx)
        return ""
    except IsADirectoryError:
        _deny(tool, "Not a file", args, ctx)
        return ""
    except PermissionError:
        _deny(tool, "Permission denied", args, ctx, deny_category="TECH_ERROR")
        return ""

    try:
        text = data.decode("utf-8")
        _log_access(
            tool,
            {"path": str(target), "returned_bytes": len(data), "encoding": "utf-8"},
            "ok",
            ctx,
            client_name=client_name or None,
        )
        return text
    except UnicodeDecodeError:
        payload = base64.b64encode(data).decode("ascii")
        _log_access(
            tool,
            {"path": str(target), "returned_bytes": len(data), "encoding": "base64"},
            "ok",
            ctx,
            client_name=client_name or None,
        )
        return f"[BINARY_BASE64]\n{payload}"


@mcp.tool()
def write_file(path: str, content: str, append: bool = False, ctx: Context | None = None) -> dict[str, Any]:
    tool = "write_file"
    args = {"path": path, "append": append, "chars": len(content)}
    client_name = _run_request_pipeline(ctx, tool, args)
    pol = _get_policy()

    try:
        target = _resolve_user_path(path, pol)
    except ValueError as error:
        _deny(tool, str(error), args, ctx)
        return {}

    if _is_blocked_file(target, pol):
        _deny(tool, "File blocked by policy", args, ctx)
        return {}

    allowed, reason = _write_allowed(target, pol, client_name)
    if not allowed:
        _deny(tool, reason or "Write not allowed", args, ctx, deny_category=DENY_POLICY)
        return {}

    pol_advanced = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    max_wb = int(pol_advanced.get("max_write_bytes", MAX_WRITE_BYTES))
    if max_wb > 0:
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > max_wb:
            _deny(tool, f"Content too large ({content_bytes} bytes, max {max_wb})", args, ctx)
            return {}

    created_parents = []
    p = target.parent
    while not p.exists() and p != p.parent:
        created_parents.append(str(p))
        p = p.parent
    target.parent.mkdir(parents=True, exist_ok=True)
    if created_parents:
        _log_access(tool, {"implicit_dirs_created": list(reversed(created_parents))}, "info", ctx, client_name=client_name or None)

    file_mode = "a" if append else "w"
    with target.open(file_mode, encoding="utf-8") as fh:
        fh.write(content)

    result = {"path": str(target), "bytes": len(content.encode("utf-8")), "append": append}
    _log_access(tool, result, "ok", ctx, client_name=client_name or None)
    return result


@mcp.tool()
def create_directory(path: str, ctx: Context | None = None) -> dict[str, Any]:
    tool = "create_directory"
    args = {"path": path}
    client_name = _run_request_pipeline(ctx, tool, args)
    pol = _get_policy()

    try:
        target = _resolve_user_path(path, pol)
    except ValueError as error:
        _deny(tool, str(error), args, ctx)
        return {}

    allowed, reason = _write_allowed(target, pol, client_name)
    if not allowed:
        _deny(tool, reason or "Write not allowed", args, ctx, deny_category=DENY_POLICY)
        return {}

    created_parents = []
    p = target
    while not p.exists() and p != p.parent:
        created_parents.append(str(p))
        p = p.parent
    target.mkdir(parents=True, exist_ok=True)
    if created_parents:
        _log_access(tool, {"implicit_dirs_created": list(reversed(created_parents))}, "info", ctx, client_name=client_name or None)

    result = {"path": str(target)}
    _log_access(tool, result, "ok", ctx, client_name=client_name or None)
    return result


@mcp.tool()
def delete_path(path: str, recursive: bool = False, ctx: Context | None = None) -> dict[str, Any]:
    tool = "delete_path"
    args = {"path": path, "recursive": recursive}
    client_name = _run_request_pipeline(ctx, tool, args)
    pol = _get_policy()

    try:
        target = _resolve_user_path(path, pol)
    except ValueError as error:
        _deny(tool, str(error), args, ctx)
        return {}

    allowed, reason = _write_allowed(target, pol, client_name)
    if not allowed:
        _deny(tool, reason or "Write not allowed", args, ctx, deny_category=DENY_POLICY)
        return {}

    if not target.exists():
        _deny(tool, "Path does not exist", args, ctx)
        return {}

    if target.is_file():
        target.unlink()
    else:
        if recursive:
            for dp, _dn, fn in os.walk(target):
                for f in fn:
                    child = Path(dp) / f
                    if _is_blocked_file(child, pol):
                        _deny(tool, f"Blocked file in subdirectory: {child.name}", args, ctx)
                        return {}
            shutil.rmtree(target)
        else:
            target.rmdir()

    result = {"path": str(target), "recursive": recursive}
    _log_access(tool, result, "ok", ctx, client_name=client_name or None)
    return result


# policy_snapshot bleibt immer registriert (Selbstauskunft / Debugging).
_PROTECTED_TOOL_NAMES = frozenset({"policy_snapshot"})


def _apply_disabled_tools_from_policy() -> None:
    """Entfernt registrierte Tools gemäß ``tool_registry.disabled_tools`` (Server-Neustart nötig)."""
    pol = _get_policy()
    tr = pol.get("tool_registry")
    if not isinstance(tr, dict):
        return
    raw = tr.get("disabled_tools")
    if not isinstance(raw, list):
        return
    removed: list[str] = []
    for item in raw:
        name = str(item).strip()
        if not name or name in _PROTECTED_TOOL_NAMES:
            continue
        try:
            mcp.remove_tool(name)
            removed.append(name)
        except Exception:
            pass
    if removed:
        print(
            "MCC MCP: the following tools are disabled by policy (not registered): "
            + ", ".join(removed),
            file=_sys.stderr,
        )


if __name__ == "__main__":
    host = (os.getenv("MCP_HOST") or os.getenv("MCC_HOST") or "127.0.0.1").strip()
    port = int((os.getenv("MCP_PORT") or os.getenv("MCC_PORT") or "8766").strip())
    path = os.getenv("MCP_PATH", "/mcp")

    _policy_integrity_startup_primary()
    _apply_disabled_tools_from_policy()

    try:
        mcp.run(transport="streamable-http", host=host, port=port, path=path)
    except TypeError:
        mcp.run(host=host, port=port)
