"""Kurzer Live-Test: MCP streamable-http starten, Port offen, HTTP /mcp antwortet.

Nutzt Repo-`config/mcp_policy.json` und freien Port (Standard 18766, überschreibbar mit SMOKE_MCP_PORT).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("SMOKE_MCP_PORT", "18766"))


def main() -> int:
    pol = ROOT / "config" / "mcp_policy.json"
    if not pol.is_file():
        print("SMOKE: missing", pol, file=sys.stderr)
        return 2

    env = os.environ.copy()
    env["MCP_POLICY_FILE"] = str(pol)
    # MCP_PORT schlägt MCC_PORT (siehe mcp_server __main__); beide setzen.
    env["MCP_PORT"] = str(PORT)
    env["MCC_PORT"] = str(PORT)
    env["MCC_LOG_DIR"] = str(ROOT / "logs")
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [sys.executable, str(ROOT / "scripts" / "mcp_server.py")]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    err_tail: list[str] = []

    def _drain_stderr() -> None:
        try:
            assert proc.stderr is not None
            for line in proc.stderr:
                err_tail.append(line)
                if len(err_tail) > 200:
                    del err_tail[:-120]
        except Exception:
            pass

    threading.Thread(target=_drain_stderr, daemon=True).start()
    try:
        deadline = time.monotonic() + 45.0
        tcp_ok = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                print("SMOKE: Server process exited with", proc.returncode, file=sys.stderr)
                if err_tail:
                    print("".join(err_tail)[-4000:], file=sys.stderr)
                return 2
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=2).close()
                tcp_ok = True
                break
            except OSError:
                time.sleep(0.5)

        if not tcp_ok:
            print("SMOKE: No TCP on port", PORT, file=sys.stderr)
            if err_tail:
                print("".join(err_tail)[-4000:], file=sys.stderr)
            return 2

        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/mcp", timeout=10)
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403, 404, 405, 406, 415, 422):
                print("SMOKE: HTTP", e.code, "(Endpoint antwortet)")
            else:
                raise
        except urllib.error.URLError as e:
            print("SMOKE: HTTP-Probe:", e.reason, file=sys.stderr)
            return 3

        print("SMOKE OK: TCP + HTTP /mcp")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=8)


if __name__ == "__main__":
    raise SystemExit(main())
