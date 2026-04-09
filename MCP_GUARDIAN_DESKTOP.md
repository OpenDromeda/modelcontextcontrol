# EVOKI Guardian Control Center (eine Anwendung)

## Ziel

Eine zentrale App statt vieler BAT-Dateien:
- Server starten/stoppen
- Tunnel starten/stoppen
- OAuth-Werte verwalten
- Policy (Allow/Deny, Read/Write) bearbeiten
- Zugriffe überwachen
- Verdächtigenliste mit Score/Flags
- JSON-Export manuell + automatisch bei Trennen/Beenden
- Hilfe-Tab mit kompletter Anleitung für GitHub OAuth + ChatGPT Connector

## Start

- Direkter Start: `scripts/start_evoki_guardian_stack.bat`
- Oder Python direkt: `python scripts/mcp_guardian_app.py`

## Installierbare EXE (Packer)

Bekannter Packer: **PyInstaller**

- Build: `scripts/build_guardian_app.bat`
- Ergebnis: `dist/EVOKI_GUARDIAN_CONTROL_CENTER.exe`

## Policy (Lese-/Schreibrechte)

Datei: `config/mcp_policy.json`

In der App im Tab `Policy` einstellbar:
- `mode`: `read_only` (Standard) oder `read_write`
- `roots`: erlaubte Wurzelpfade
- `write_allow_paths`: optionale Schreib-Allowlist
- `write_deny_paths`: Schreib-Denylist (hat Vorrang)
- Verbotslisten:
  - gesperrte Ordnernamen
  - gesperrte Pfadteile
  - gesperrte Dateiendungen
  - gesperrte Dateinamen
  - gesperrte Namens-Tokens

Standard ist identisch zur aktuellen sicheren Konfiguration.

## Monitoring & Export

- Logs: `logs/mcp_access.jsonl`
- UI zeigt:
  - alle Zugriffe
  - verdächtige Zugriffe (Score + Flags)
- Export:
  - manuell per Button
  - automatisch bei `Trennen + Export`
  - automatisch beim Schließen
- Exportziel: `Downloads/evoki_access_*.json`

## Hilfe-Bereich in der App

Tab `Hilfe` enthält:
- vollständigen Schnellstart
- GitHub OAuth Konfiguration
- ChatGPT Connector Einstellungen (OAuth + DCR)
- Troubleshooting-Liste
- Button zum Speichern der Hilfe als Textdatei

## GPT/ChatGPT anschließen

1. In der App zuerst `Stack starten`
2. Tunnel-URL wird erkannt und angezeigt (`...trycloudflare.com/mcp`)
3. In ChatGPT Connector:
   - URL des MCP-Servers: die angezeigte Tunnel-URL + `/mcp`
   - Authentifizierung: OAuth
4. Bei OAuth-Consent zustimmen

Hinweis: Bei neuer Tunnel-Domain müssen OAuth-Provider-URLs (Homepage/Callback) entsprechend aktualisiert werden.

## Verfügbare Tools

- `policy_snapshot`
- `list_roots`
- `list_directory`
- `search_files`
- `read_file`
- `write_file` (nur bei `read_write` + Policy erlaubt)
- `create_directory` (nur bei `read_write` + Policy erlaubt)
- `delete_path` (nur bei `read_write` + Policy erlaubt)
