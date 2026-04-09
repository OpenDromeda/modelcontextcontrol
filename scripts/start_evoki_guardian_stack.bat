@echo off
setlocal
set ROOT=%~dp0..
cd /d "%ROOT%"

if not exist "%ROOT%\logs" mkdir "%ROOT%\logs"
echo [MCC] Starte MCP Guardian Server ...
start "MCC Guardian" cmd /c "py -3 .\scripts\mcp_readonly_evoki.py"
endlocal
