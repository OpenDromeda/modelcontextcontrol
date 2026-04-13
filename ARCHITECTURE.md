# MCC Architecture

## Project structure

```
C:\MCC
│
├─ build_mcc.bat              # Build script
├─ MCC.spec                   # PyInstaller spec
├─ dist\MCC.exe              # Built release executable
├─ config\mcp_policy.example.json  # Policy template
├─ logs\                     # Audit / access logs
├─ scripts\
│   ├─ mcp_server.py          # FastMCP MCP server
│   ├─ mcc_app.py             # MCC GUI / policy controller
│   ├─ mcc_i18n.py            # Locale selection (DE / EN)
│   ├─ smoke_mcp_server.py    # Smoke test runner
│   ├─ start_mcc.bat          # Start helper script
│   ├─ stop_mcc.bat           # Stop helper script
│   ├─ stop_mcc.py            # Stop helper helper script
│   ├─ HELP.md                # English help content
│   └─ HILFE.md               # German help content
└─ tests\
    └─ test_mcc_lite.py       # Release gate / regression tests
```

## Component roles

- `mcp_server.py`
  - core MCP server implementation
  - reads policy and enforces file-tool governance
  - writes audit/access logs

- `mcc_app.py`
  - local GUI for policy management and server control
  - displays status, logs, and settings

- `mcc_i18n.py`
  - handles language selection and help page loading

- `config/mcp_policy.example.json`
  - secure-by-default policy template for public releases

- `smoke_mcp_server.py`
  - validates server startup and `/mcp` endpoint behavior

- `build_mcc.bat` + `MCC.spec`
  - package the application into `dist\MCC.exe`

- `dist/MCC.exe`
  - final built executable for release

- `logs/`
  - runtime audit/access logs, currently empty in the clean repo

- `tests/test_mcc_lite.py`
  - regression tests covering release gate requirements

## Notes

- The root repository is intentionally lean: only public release artifacts and source files remain.
- Runtime-only files are excluded from git via `.gitignore`.
