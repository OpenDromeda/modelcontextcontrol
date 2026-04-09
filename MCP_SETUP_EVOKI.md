# MCP-Zugang für ChatGPT (C, D, J read-only, mit kritischen Sperrfiltern)

Diese Anleitung richtet einen read-only MCP-Zugang für `C:\`, `D:\` und `J:\` ein.

## 1) Python-Paket installieren

```powershell
pip install fastmcp
```

## 2) Server lokal starten

Im Projektordner:

```powershell
python .\scripts\mcp_readonly_evoki.py
```

Standard-Endpunkt lokal:

- `http://127.0.0.1:8765/mcp`

Optional per Umgebungsvariablen:

- `EVOKI_MCP_ROOTS` (z. B. `C:\;D:\;J:\`)
- `EVOKI_MCP_ROOT` (Legacy, einzelner Root)
- `MCP_HOST` (Standard: `127.0.0.1`)
- `MCP_PORT` (Standard: `8765`)
- `MCP_PATH` (Standard: `/mcp`)

## 3) Per HTTPS nach außen (Tunnel)

Beispiel mit Cloudflare Tunnel:

```powershell
cloudflared tunnel --url http://127.0.0.1:8765
```

Du bekommst eine öffentliche HTTPS-URL, z. B.:

- `https://dein-name.trycloudflare.com/mcp`

## 4) In ChatGPT verbinden

In ChatGPT:

1. `Settings`
2. `Apps & Connectors`
3. `Create`
4. Eintragen:
   - Name: `EVOKI Local Readonly`
   - Beschreibung: `Liest und durchsucht freigegebene EVOKI-Dateien (read-only)`
   - MCP URL: `https://.../mcp`

## 4b) OAuth aktivieren (empfohlen)

Der Server unterstützt optional OAuth per Env-Variablen:

- `MCP_AUTH_MODE=github` (oder `google`, `oidc`)
- `MCP_PUBLIC_BASE_URL=https://dein-tunnel.trycloudflare.com`
- `MCP_OAUTH_CLIENT_ID=...`
- `MCP_OAUTH_CLIENT_SECRET=...`
- optional: `MCP_OAUTH_REDIRECT_PATH=/oauth/callback`
- optional: `MCP_OAUTH_SCOPES=openid,profile,email`
- nur für `oidc`: `MCP_OIDC_CONFIG_URL=https://.../.well-known/openid-configuration`

Beispielstart mit GitHub OAuth:

```powershell
$env:MCP_AUTH_MODE='github'
$env:MCP_PUBLIC_BASE_URL='https://dein-tunnel.trycloudflare.com'
$env:MCP_OAUTH_CLIENT_ID='DEIN_CLIENT_ID'
$env:MCP_OAUTH_CLIENT_SECRET='DEIN_CLIENT_SECRET'
$env:MCP_PORT='8766'
python .\scripts\mcp_readonly_evoki.py
```

Im ChatGPT-Connector bei Authentifizierung `OAuth` wählen und den Flow durchlaufen.

### GitHub OAuth App in 2 Minuten

1. Öffne GitHub: `Settings` → `Developer settings` → `OAuth Apps` → `New OAuth App`
2. Felder setzen:
   - `Application name`: frei wählbar (z. B. `EVOKI MCP`)
   - `Homepage URL`: deine Tunnel-Basis (z. B. `https://parliamentary-resume-expo-machine.trycloudflare.com`)
   - `Authorization callback URL`: `https://parliamentary-resume-expo-machine.trycloudflare.com/oauth/callback`
3. App speichern und danach `Client ID` + `Client Secret` kopieren.
4. Server im OAuth-Modus starten:

```powershell
.\scripts\start_mcp_github_oauth.ps1
```

5. In ChatGPT im Connector:
   - `URL des MCP-Servers`: `https://parliamentary-resume-expo-machine.trycloudflare.com/mcp`
   - `Authentifizierung`: `OAuth`

Hinweis: Bei jeder neuen Quick-Tunnel-URL musst du in GitHub die `Homepage URL` und `Authorization callback URL` auf die neue Domain aktualisieren.

## 5) Verfügbare Tools

- `list_roots()`
- `list_directory(path=".")`
- `search_files(query, limit=100)`
- `read_file(path, max_bytes=200000)`

## Sicherheitsrahmen

- Nur freigegebene Roots (`C:\`, `D:\`, `J:\` bzw. `EVOKI_MCP_ROOTS`)
- Gesperrte kritische Ordner/Pfade: `.git`, `Windows`, `ProgramData`, `AppData`, `.ssh`, `.gnupg`, `$Recycle.Bin`, `System Volume Information`
- Gesperrte kritische Dateitypen: `.env`, `.env.*`, `.key`, `.pem`, `.pfx`, `.p12`, `.kdbx`, `.ovpn`
- Gesperrte sensitive Dateinamen/-muster: `id_rsa`, `id_ed25519`, `authorized_keys`, `known_hosts`, `credentials`, Namen mit `secret|token|password|api_key|private_key`
- Binärdateien werden von `read_file` als Base64 mit Prefix `[BINARY_BASE64]` zurückgegeben

## Hinweis bei Voll-Laufwerken

- Suche über ganze Laufwerke kann langsam sein.
- Manche Systemordner liefern Zugriffsfehler; der Server überspringt diese automatisch.
- Trotz Voll-Roots sind typische System- und Secret-Bereiche aktiv blockiert.
