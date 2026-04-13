import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PORTS = {8765, 8766, 20242}


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout or ""


def _kill_pid(pid: int) -> None:
    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True, check=False)


def _pids_from_netstat() -> set[int]:
    out = _run(["netstat", "-ano"])
    found: set[int] = set()
    for line in out.splitlines():
        norm = re.sub(r"\s+", " ", line).strip()
        if not norm:
            continue
        for port in PORTS:
            if f":{port} " in norm:
                parts = norm.split(" ")
                if parts and parts[-1].isdigit():
                    found.add(int(parts[-1]))
    return found


def _query_pids_from_powershell() -> set[int]:
    ps = (
        "$procs = Get-CimInstance Win32_Process | Where-Object {"
        " ($_.Name -match '^python(\\.exe)?$' -and $_.CommandLine -like '*mcp_server.py*')"
        " -or ($_.Name -ieq 'cloudflared.exe')"
        "};"
        "$procs | Select-Object -ExpandProperty ProcessId | ConvertTo-Json -Compress"
    )
    out = _run(["powershell", "-NoProfile", "-Command", ps]).strip()
    if not out:
        return set()

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return set()

    if isinstance(data, int):
        return {data}
    if isinstance(data, list):
        return {int(x) for x in data if isinstance(x, int) or (isinstance(x, str) and x.isdigit())}
    return set()


def main() -> None:
    print("[MCC] Stoppe MCP/Tunnel Prozesse ...")
    targets = _pids_from_netstat() | _query_pids_from_powershell()
    for pid in sorted(targets):
        _kill_pid(pid)

    subprocess.run(["taskkill", "/F", "/IM", "cloudflared.exe"], capture_output=True, text=True, check=False)
    print(f"[MCC] Stack gestoppt. Beendete Kandidaten: {len(targets)}")


if __name__ == "__main__":
    main()
