import base64
import json
import os
import secrets
import shutil
import subprocess
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


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOG_DIR = BASE_DIR / "logs"
DEFAULT_POLICY_PATH = CONFIG_DIR / "mcp_policy.json"
KONTEXT_RUNNER_CONFIG_PATH = CONFIG_DIR / "mcp_kontext_runner.json"
SESSION_ID = uuid.uuid4().hex

_DEFAULT_KONTEXT_RUNNER: dict[str, Any] = {
    "script_relative": "KONTEXT/scripts/cowork_kontext_hourly.py",
    "timeout_seconds": 7200,
    "max_output_chars_per_stream": 120_000,
}

RATE_STATE_PATH = CONFIG_DIR / "rate_state.json"

def _load_startup_secrets() -> dict[str, Any]:
    """OAuth/Bearer-Startwerte: zuerst ``MCP_SECRETS_FILE`` (Guardian), sonst stdin (Legacy)."""
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
                        print(f"EVOKI MCP: JSON in MCP_SECRETS_FILE ungültig: {exc}", file=_sys.stderr)
        except OSError as exc:
            print(f"EVOKI MCP: MCP_SECRETS_FILE konnte nicht gelesen werden: {exc}", file=_sys.stderr)
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
            print(f"EVOKI MCP: JSON von stdin ungültig: {exc}", file=_sys.stderr)
            return {}
    except Exception as exc:
        print(f"EVOKI MCP: stdin lesen fehlgeschlagen: {exc}", file=_sys.stderr)
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
    "roots": ["C:/", "D:/", "J:/"],
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
            ".env.local",
            ".env.development",
            ".env.production",
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
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    path.write_text(json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_policy() -> dict[str, Any]:
    policy_path = Path(os.getenv("MCP_POLICY_FILE", str(DEFAULT_POLICY_PATH))).resolve()
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
        raise ValueError("MCP_PUBLIC_BASE_URL fehlt für OAuth-Modus")
    if not client_id or not client_secret:
        raise ValueError("MCP_OAUTH_CLIENT_ID/MCP_OAUTH_CLIENT_SECRET fehlen")

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
            raise ValueError("MCP_OIDC_CONFIG_URL fehlt für OIDC-Modus")

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

    raise ValueError(f"Unbekannter MCP_AUTH_MODE: {mode}")


try:
    mcp = FastMCP("EVOKI V5 Guarded", auth=_build_auth_provider())
except Exception as exc:
    import sys as _sys

    print(f"EVOKI MCP: Initialisierung fehlgeschlagen: {exc}", file=_sys.stderr)
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

    if not parsed:
        parsed = [Path("C:/").resolve(), Path("D:/").resolve(), Path("J:/").resolve()]
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
    ip = _get_real_ip(ctx)

    ok_bl, bl_detail = _check_blocklist(ip)
    if not ok_bl:
        _deny(tool, "IP blockiert", args, ctx, deny_category=DENY_AUTH, deny_detail=bl_detail)

    ok_rl, rl_detail = _check_rate_limit(ip, pol)
    if not ok_rl:
        _deny(tool, rl_detail or "Zu viele Anfragen", args, ctx, deny_category=DENY_RATE, deny_detail=rl_detail)

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
            _deny(tool, "Client gesperrt", args, ctx, deny_category=DENY_AUTH, deny_detail=cb_detail)
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


def _is_blocked_file(path: Path, pol: dict[str, Any]) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    blocked_suffixes = _blocked_set_from_pol(pol, "suffixes")
    blocked_file_names = _blocked_set_from_pol(pol, "file_names")
    blocked_name_contains = _blocked_set_from_pol(pol, "name_contains")

    if suffix in blocked_suffixes:
        return True
    if name in blocked_file_names:
        return True

    if _is_in_honeypot_zone(path, pol):
        return False

    if any(token in name for token in blocked_name_contains):
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
            raise ValueError("Alternate Data Streams nicht erlaubt")
        if raw.startswith("\\\\"):
            raise ValueError("UNC-Pfade nicht erlaubt")

    allowed_roots = _roots_from_policy_dict(pol)
    candidate = Path(raw)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (allowed_roots[0] / candidate).resolve()

    if normalize:
        resolved = Path(_get_long_path_name(str(resolved)))

    if not _is_under_allowed_root(resolved, allowed_roots):
        raise ValueError("Pfad nicht erlaubt")
    if _is_blocked_path(resolved, pol):
        raise ValueError("Pfad gesperrt")
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
        return False, "Server läuft im read_only Modus"

    permissions = pol.get("permissions", {})
    if not isinstance(permissions, dict):
        return False, "Ungültige permissions Konfiguration"

    deny_paths = permissions.get("write_deny_paths", [])
    if not isinstance(deny_paths, list):
        deny_paths = []

    if deny_paths and _path_matches_prefixes(path, [str(v) for v in deny_paths]):
        return False, "Pfad in write_deny_paths"

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
        return False, "Keine write_allow_paths konfiguriert"
    if not _path_matches_prefixes(path, [str(v) for v in allow_paths]):
        return False, "Pfad nicht in write_allow_paths"

    return True, None


def _kontext_hourly_env_enabled() -> bool:
    v = (os.environ.get("MCP_ALLOW_KONTEXT_HOURLY") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _terminal_exec_env_enabled() -> bool:
    v = (os.environ.get("MCP_ALLOW_TERMINAL_EXEC") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _windows_confirm_terminal_execution(command: str, workdir: str) -> bool:
    """Explizite Zustimmung am interaktiven Windows-Desktop (MessageBox)."""
    if os.name != "nt":
        return False
    MB_YESNO = 0x00000004
    MB_ICONWARNING = 0x00000030
    IDYES = 6
    preview = command if len(command) <= 1200 else command[:1170] + "\n…"
    wd = workdir if len(workdir) <= 500 else workdir[:480] + "…"
    msg = (
        "Der MCP-Client möchte folgenden Befehl ausführen:\n\n"
        f"{preview}\n\n"
        f"Arbeitsverzeichnis:\n{wd}\n\n"
        "Ja = Ausführen, Nein = Abbrechen"
    )
    r = int(ctypes.windll.user32.MessageBoxW(0, msg, "EVOKI MCP – Terminal", MB_YESNO | MB_ICONWARNING))
    return r == IDYES


def _load_kontext_runner_cfg() -> dict[str, Any]:
    cfg: dict[str, Any] = dict(_DEFAULT_KONTEXT_RUNNER)
    if not KONTEXT_RUNNER_CONFIG_PATH.is_file():
        return cfg
    try:
        raw = json.loads(KONTEXT_RUNNER_CONFIG_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            for key, val in raw.items():
                if str(key).startswith("_"):
                    continue
                cfg[str(key)] = val
    except (OSError, json.JSONDecodeError):
        pass
    return cfg


def _truncate_text(text: str, max_chars: int) -> str:
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 24)] + "\n... [Ausgabe gekürzt] ..."


@mcp.tool()
def run_kontext_cowork_hourly(ctx: Context | None = None) -> dict[str, Any]:
    """Führt die stündliche Kontext-Kette auf dem EVOKI-Host aus (Delta → Index → Snapshot).

    Nur aktiv, wenn im Guardian Control Center der Haken gesetzt und der Stack gestartet wurde.

    Hinweis Timeout: ``timeout_seconds`` in ``config/mcp_kontext_runner.json`` begrenzt nur den
    **Subprozess** auf dem Server (Standard 7200s). Viele MCP-Clients beenden den **HTTP-Tool-Aufruf**
    dagegen oft nach ~60s — die Kette kann auf dem Host trotzdem fertig werden; siehe Doku
    EVOKI KONTEXT Stunde (Timeouts).
    """
    tool = "run_kontext_cowork_hourly"
    args: dict[str, Any] = {}
    client_name = _run_request_pipeline(ctx, tool, args)

    if not _kontext_hourly_env_enabled():
        detail = "Im Guardian: Haken „Kontext-Stunde per MCP“ vor „Stack starten“ setzen."
        _log_access(
            tool,
            {"ok": False},
            "denied",
            ctx,
            reason=detail,
            client_name=client_name or None,
            deny_category=DENY_POLICY,
            deny_detail="kontext_runner_guardian_off",
        )
        return {"ok": False, "error": "guardian_kontext_mcp_off", "detail": detail}

    cfg = _load_kontext_runner_cfg()
    rel = str(cfg.get("script_relative") or _DEFAULT_KONTEXT_RUNNER["script_relative"])
    script_path = (BASE_DIR / rel).resolve()
    base_resolved = BASE_DIR.resolve()
    try:
        script_path.relative_to(base_resolved)
    except ValueError:
        msg = "script_relative liegt ausserhalb von BASE_DIR"
        _log_access(tool, {"ok": False}, "denied", ctx, reason=msg, client_name=client_name or None, deny_category=DENY_POLICY)
        return {"ok": False, "error": "invalid_script_path", "detail": msg}

    if not script_path.is_file():
        msg = f"Script fehlt: {script_path}"
        _log_access(tool, {"ok": False}, "denied", ctx, reason=msg, client_name=client_name or None, deny_category=DENY_TECH)
        return {"ok": False, "error": "script_missing", "path": str(script_path)}

    try:
        timeout_s = int(cfg.get("timeout_seconds") or 7200)
    except (TypeError, ValueError):
        timeout_s = 7200
    timeout_s = max(60, min(timeout_s, 86_400))

    try:
        max_out = int(cfg.get("max_output_chars_per_stream") or 120_000)
    except (TypeError, ValueError):
        max_out = 120_000
    max_out = max(4000, min(max_out, 2_000_000))

    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    cmd = [_sys.executable, str(script_path)]
    sub_env = os.environ.copy()
    sub_env.setdefault("PYTHONIOENCODING", "utf-8")
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(base_resolved),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            creationflags=flags,
            env=sub_env,
        )
    except subprocess.TimeoutExpired as exc:
        dur = round(time.monotonic() - t0, 2)
        _log_access(
            tool,
            {"ok": False, "timeout_s": timeout_s, "duration_s": dur},
            "denied",
            ctx,
            reason="Timeout",
            client_name=client_name or None,
            deny_category=DENY_TECH,
        )
        return {
            "ok": False,
            "error": "timeout",
            "timeout_seconds": timeout_s,
            "server_subprocess_timeout_seconds": timeout_s,
            "duration_s": dur,
            "partial_stdout": _truncate_text((exc.stdout or ""), max_out),
            "partial_stderr": _truncate_text((exc.stderr or ""), max_out),
        }
    except OSError as exc:
        _log_access(
            tool,
            {"ok": False, "exc": str(exc)},
            "denied",
            ctx,
            reason=str(exc),
            client_name=client_name or None,
            deny_category=DENY_TECH,
        )
        return {
            "ok": False,
            "error": "os_error",
            "detail": str(exc),
            "server_subprocess_timeout_seconds": timeout_s,
        }

    dur = round(time.monotonic() - t0, 2)
    out = _truncate_text(proc.stdout or "", max_out)
    err = _truncate_text(proc.stderr or "", max_out)
    payload = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "duration_s": dur,
        "server_subprocess_timeout_seconds": timeout_s,
        "cwd": str(base_resolved),
        "command": cmd,
        "stdout": out,
        "stderr": err,
    }
    _log_access(
        tool,
        {
            "ok": payload["ok"],
            "returncode": proc.returncode,
            "duration_s": dur,
            "stdout_chars": len(out),
            "stderr_chars": len(err),
            "response_bytes": _json_size_bytes(payload),
        },
        "ok" if payload["ok"] else "error",
        ctx,
        reason=None if payload["ok"] else f"exit_{proc.returncode}",
        client_name=client_name or None,
        deny_category=None if payload["ok"] else DENY_TECH,
    )
    return payload


@mcp.tool()
def run_terminal_command(
    command: str,
    cwd: Optional[str] = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Führt einen Shell-Befehl auf dem Host aus (nur mit Guardian-Haken und pro Aufruf Windows-Bestätigung)."""
    tool = "run_terminal_command"
    args: dict[str, Any] = {"command_preview_chars": min(len(command), 200)}
    client_name = _run_request_pipeline(ctx, tool, args)

    if not _terminal_exec_env_enabled():
        detail = "Im Guardian: Haken „Terminal per MCP“ mit Master-Passwort vor „Stack starten“ setzen."
        _log_access(
            tool,
            {"ok": False},
            "denied",
            ctx,
            reason=detail,
            client_name=client_name or None,
            deny_category=DENY_POLICY,
            deny_detail="terminal_exec_guardian_off",
        )
        return {"ok": False, "error": "guardian_terminal_mcp_off", "detail": detail}

    if len(command) > 16_000:
        _log_access(
            tool,
            {"ok": False},
            "denied",
            ctx,
            reason="Befehl zu lang",
            client_name=client_name or None,
            deny_category=DENY_POLICY,
        )
        return {"ok": False, "error": "command_too_long", "max_chars": 16_000}

    base_resolved = BASE_DIR.resolve()
    work = base_resolved
    if cwd and str(cwd).strip():
        try:
            work = Path(cwd).expanduser().resolve()
            work.relative_to(base_resolved)
        except (ValueError, OSError) as exc:
            msg = f"cwd ausserhalb von BASE_DIR oder ungültig: {exc}"
            _log_access(
                tool,
                {"ok": False, "cwd": str(cwd)},
                "denied",
                ctx,
                reason=msg,
                client_name=client_name or None,
                deny_category=DENY_POLICY,
            )
            return {"ok": False, "error": "invalid_cwd", "detail": msg}

    if os.name != "nt":
        _log_access(
            tool,
            {"ok": False},
            "denied",
            ctx,
            reason="Terminal-Bestätigung nur unter Windows (MessageBox)",
            client_name=client_name or None,
            deny_category=DENY_TECH,
        )
        return {"ok": False, "error": "windows_only", "detail": "MessageBox-Bestätigung ist nur unter Windows verfügbar."}

    if not _windows_confirm_terminal_execution(command, str(work)):
        _log_access(
            tool,
            {"ok": False},
            "denied",
            ctx,
            reason="Benutzer hat Ausführung abgelehnt (MessageBox)",
            client_name=client_name or None,
            deny_category=DENY_POLICY,
            deny_detail="terminal_user_declined",
        )
        return {"ok": False, "error": "user_declined", "detail": "Ausführung am Desktop abgelehnt."}

    max_out = 80_000
    timeout_s = 300
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(work),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            creationflags=flags,
        )
    except subprocess.TimeoutExpired as exc:
        dur = round(time.monotonic() - t0, 2)
        _log_access(
            tool,
            {"ok": False, "timeout_s": timeout_s, "duration_s": dur},
            "denied",
            ctx,
            reason="Timeout",
            client_name=client_name or None,
            deny_category=DENY_TECH,
        )
        return {
            "ok": False,
            "error": "timeout",
            "timeout_seconds": timeout_s,
            "duration_s": dur,
            "partial_stdout": _truncate_text((exc.stdout or ""), max_out),
            "partial_stderr": _truncate_text((exc.stderr or ""), max_out),
        }
    except OSError as exc:
        _log_access(
            tool,
            {"ok": False, "exc": str(exc)},
            "denied",
            ctx,
            reason=str(exc),
            client_name=client_name or None,
            deny_category=DENY_TECH,
        )
        return {"ok": False, "error": "os_error", "detail": str(exc)}

    dur = round(time.monotonic() - t0, 2)
    out = _truncate_text(proc.stdout or "", max_out)
    err = _truncate_text(proc.stderr or "", max_out)
    payload = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "duration_s": dur,
        "cwd": str(work),
        "stdout": out,
        "stderr": err,
    }
    _log_access(
        tool,
        {
            "ok": payload["ok"],
            "returncode": proc.returncode,
            "duration_s": dur,
            "stdout_chars": len(out),
            "stderr_chars": len(err),
            "response_bytes": _json_size_bytes(payload),
        },
        "ok" if payload["ok"] else "error",
        ctx,
        reason=None if payload["ok"] else f"exit_{proc.returncode}",
        client_name=client_name or None,
        deny_category=None if payload["ok"] else DENY_TECH,
    )
    return payload


@mcp.tool()
def policy_snapshot(ctx: Context | None = None) -> dict[str, Any]:
    args: dict[str, Any] = {}
    client_name = _run_request_pipeline(ctx, "policy_snapshot", args)
    pol = _get_policy()
    roots = _roots_from_policy_dict(pol)
    snapshot = {
        "policy_path": pol.get("_policy_path"),
        "roots": [str(r) for r in roots],
        "mode": _write_mode(pol),
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
        _deny(tool, "Pfad existiert nicht", args, ctx)
        return []
    if not target.is_dir():
        _deny(tool, "Kein Ordner", args, ctx)
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
def search_files(query: str, limit: int = 100, ctx: Context | None = None) -> list[str]:
    tool = "search_files"
    args = {"query": query, "limit": limit}
    client_name = _run_request_pipeline(ctx, tool, args)
    pol = _get_policy()
    q = query.strip().lower()
    if not q:
        _deny(tool, "Query darf nicht leer sein", args, ctx)
        return []
    if limit < 1:
        _deny(tool, "limit muss >= 1 sein", args, ctx)
        return []

    max_hits = min(limit, 500)
    hits: list[str] = []

    all_roots = _roots_from_policy_dict(pol)
    write_paths = pol.get("permissions", {}).get("write_allow_paths", [])
    if not isinstance(write_paths, list):
        write_paths = []
    wp_resolved = [Path(p).resolve() for p in write_paths if isinstance(p, str) and p.strip()]

    priority_roots = []
    other_roots = []
    for r in all_roots:
        is_priority = any(_is_under_allowed_root(wp, [r]) or r == wp for wp in wp_resolved)
        if is_priority:
            priority_roots.append(r)
        else:
            other_roots.append(r)

    adv = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    do_prioritize = adv.get("search_prioritize_write_paths", True)
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

    try:
        with target.open("rb") as fh:
            if _is_blocked_file(target, pol):
                _deny(tool, "Datei gesperrt", args, ctx)
                return ""
            if not target.is_file():
                _deny(tool, "Keine Datei", args, ctx)
                return ""
            max_len = 2000 if max_bytes < 2000 else min(max_bytes, 2_000_000)
            data = fh.read(max_len)
    except FileNotFoundError:
        _deny(tool, "Datei existiert nicht", args, ctx)
        return ""
    except IsADirectoryError:
        _deny(tool, "Keine Datei", args, ctx)
        return ""
    except PermissionError:
        _deny(tool, "Keine Berechtigung", args, ctx, deny_category="TECH_ERROR")
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
        _deny(tool, "Datei gesperrt", args, ctx)
        return {}

    allowed, reason = _write_allowed(target, pol, client_name)
    if not allowed:
        _deny(tool, reason or "Schreiben nicht erlaubt", args, ctx, deny_category=DENY_POLICY)
        return {}

    pol_advanced = pol.get("advanced") if isinstance(pol.get("advanced"), dict) else {}
    max_wb = int(pol_advanced.get("max_write_bytes", MAX_WRITE_BYTES))
    if max_wb > 0:
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > max_wb:
            _deny(tool, f"Content zu gross ({content_bytes} Bytes, max {max_wb})", args, ctx)
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
        _deny(tool, reason or "Schreiben nicht erlaubt", args, ctx, deny_category=DENY_POLICY)
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
        _deny(tool, reason or "Schreiben nicht erlaubt", args, ctx, deny_category=DENY_POLICY)
        return {}

    if not target.exists():
        _deny(tool, "Pfad existiert nicht", args, ctx)
        return {}

    if target.is_file():
        target.unlink()
    else:
        if recursive:
            for dp, _dn, fn in os.walk(target):
                for f in fn:
                    child = Path(dp) / f
                    if _is_blocked_file(child, pol):
                        _deny(tool, f"Gesperrte Datei im Unterverzeichnis: {child.name}", args, ctx)
                        return {}
            shutil.rmtree(target)
        else:
            target.rmdir()

    result = {"path": str(target), "recursive": recursive}
    _log_access(tool, result, "ok", ctx, client_name=client_name or None)
    return result


if __name__ == "__main__":
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "8766"))
    path = os.getenv("MCP_PATH", "/mcp")

    try:
        mcp.run(transport="streamable-http", host=host, port=port, path=path)
    except TypeError:
        mcp.run(host=host, port=port)
