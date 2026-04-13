# -*- mode: python ; coding: utf-8 -*-
# MCC — 7-Tab GUI
# Die GUI startet mcp_server.py als SEPARATEN Python-Prozess.
# Daher wird fastmcp NICHT eingebettet — nur tkinter + cryptography.

import os

_ROOT = os.path.dirname(os.path.abspath(SPEC))
_SCRIPTS = os.path.join(_ROOT, "scripts")

datas = []
for _name in ("HILFE.md", "HELP.md"):
    _p = os.path.join(_SCRIPTS, _name)
    if os.path.isfile(_p):
        datas.append((_p, "."))

a = Analysis(
    [os.path.join("scripts", "mcp_guardian_app.py")],
    pathex=[_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "fastmcp", "uvicorn", "fastapi", "starlette",
        "numpy", "pandas", "scipy", "torch", "matplotlib",
        "PIL", "IPython", "jupyter", "notebook",
        "google", "grpc", "openai", "anthropic",
        "psutil", "zmq", "lxml", "docutils",
        "pytest", "setuptools", "pip",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="MCC",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Windows shell / Explorer: keep EXE basename aligned with MCC (ProductName via external version resource optional).
)
