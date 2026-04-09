@echo off
setlocal
set ROOT=%~dp0..
cd /d "%ROOT%"

py -3 .\scripts\stop_evoki_guardian_stack.py
endlocal
