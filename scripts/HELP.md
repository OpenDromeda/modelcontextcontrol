MCC — HELP
==========

MCC is currently documented in German only. The full reference is in
`HILFE.md` (bundled next to this file).

An English translation is planned for v1.1.0. Until then, this short
quick-reference covers the basics.

QUICK REFERENCE
---------------

1. First start
   - Choose a master password (minimum 12 characters).
   - The keystore is encrypted locally with PBKDF2 + Fernet.
   - Without the correct password, the MCP server will not start.
   - Forgotten password: only recovery is "Reset keystore" (loses all
     keys including OAuth).

2. Starting the stack
   - Click "Start stack". This launches the MCP server and runs the
     self-test (16-point check).
   - Auth mode "github" (default): create a GitHub OAuth App, store
     Client ID and Secret in the Auth/Connector tab, save to keystore.
   - Alternative auth modes: "bearer" (per-client tokens), "none"
     (no OAuth, only for trusted local environments), "google", "oidc".

3. Tabs overview
   - Monitoring: live access log with filters (tool, outcome, search,
     time window), masked sensitive paths by default.
   - Policy: roots, read/write mode, write_allow_paths, blocklists,
     tool toggles, profiles.
   - Auth/Connector: OAuth configuration, bearer keys, public base URL,
     callback URL, connectivity test.
   - Blocklist: policy-level path blocklists and IP blocklist (table
     editor + JSON view).
   - Operations: server start/stop, health check, auto-timeout, build,
     operations log.
   - Advanced: max write bytes, search prioritization, path
     normalization, recursive delete check, GUI auto-lock, log
     retention, geo tracking, policy integrity (SHA256).
   - Help: this file.

4. Configuration files (config/)
   - mcp_policy.json — runtime policy (roots, permissions, blocked
     lists, tool registry, advanced settings)
   - keystore.enc + keystore.salt — encrypted bearer/OAuth secrets
   - blocked_ips.json — IP blocklist
   - mcc_ui.json — GUI preferences (UI locale, monitor filters,
     public base URL, OAuth secret rotation timestamp)
   - rate_state.json — rate limiting state
   - policy_integrity_startup.json — SHA256 baseline marker

5. Environment variables
   - MCC_HOME — base directory (default: ~/.mcc)
   - MCC_POLICY_PATH / MCP_POLICY_FILE — policy JSON path
   - MCC_LOG_DIR — access log directory
   - MCC_HOST / MCP_HOST — bind address (default: 127.0.0.1)
   - MCC_PORT / MCP_PORT — TCP port (default: 8766)
   - MCP_PATH — MCP endpoint path (default: /mcp)
   - MCC_LOCALE — GUI language (de or en) when no saved preference

6. Switching the GUI to English
   - View → Language → English

7. Where to read more
   - HILFE.md — full German documentation
   - README_EN.md — project overview in English
   - https://modelcontextcontrol.io — community site

8. Reporting issues / Contact
   - https://github.com/EvolutionKi/modelcontextcontrol
   - contact@opendromeda.org
