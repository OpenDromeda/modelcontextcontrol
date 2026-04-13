# MCC — Model Context Control (English summary)

**Community site:** [https://modelcontextcontrol.io/](https://modelcontextcontrol.io/)  
**Source code:** [https://github.com/EvolutionKi/modelcontextcontrol](https://github.com/EvolutionKi/modelcontextcontrol)

> Who builds a server they cannot control?

**MCC** is the open **governance layer** for the **Model Context Protocol (MCP)**. MCP defines how AI systems talk to tools; MCC defines **who** may use MCP — and **under what rules**.

## What MCC does (product scope)

- **Policy enforcement** — which tools, actors, and conditions are allowed  
- **Audit logging** — MCP calls are recorded, traceable, and reversible  
- **Rate limiting** — protect local resources from runaway agents  
- **Blocklists** — block risky or untrusted tool patterns by name  
- **Transparent errors** — failures are visible and documented, never hidden  

## Why MCC?

The MCP ecosystem is large and growing; many local installs have **no** governance layer. MCC is that layer — **open, free, and neutral**.

## Philosophy

> A system that makes its failures visible and fixable is the only system worth trusting.

## Roadmap (high level)

- Core policy engine (JSON, hot-reload capable)  
- Append-only audit log (SQLite)  
- CLI (`mcc validate`, `mcc status`, `mcc log`)  
- Docker image for self-hosted deployment  
- Integration guides for common MCP server setups  

## Domains

| Domain | Role |
|--------|------|
| [modelcontextcontrol.org](https://modelcontextcontrol.org/) | Primary — open source |
| [modelcontextcontrol.com](https://modelcontextcontrol.com/) | International |
| [modelcontextcontrol.io](https://modelcontextcontrol.io/) | Technology community |

**License:** MIT — free for everyone.

---

## MCC Lite (this repository)

MCC **Lite** is the **local policy and logging layer** for MCP **file** tools in this repo: it runs beside your client and enforces **roots**, **read/write mode**, and **blocklists** before file operations execute.

## What MCC Lite does **not** do

- **No cloud trust by default:** Public tunnel URLs are optional; the default is localhost only.
- **No shell execution:** `run_terminal_command` is **not** part of MCC Lite.
- **No hourly context/cowork scans:** `run_kontext_cowork_hourly` is **not** part of MCC Lite (reserved for extended editions).
- **No automated Python script execution:** The MCC GUI does not run scheduled or on-demand Python scripts from the policy (removed from MCC Lite).
- **No automatic wide-open disks:** The server default policy uses **empty roots** until you configure them. The **bundled** `config/mcp_policy.json` in this repo may ship wider example roots (e.g. drive letters) for developer setups — treat it as a template, not the strict public default.
- **No recovery of your master password:** The keystore is encrypted locally; lost passwords cannot be reset by the vendor.

## Configuration (environment)

| Variable | Role |
|----------|------|
| `MCC_HOME` | Base directory (default: `~/.mcc`) |
| `MCC_POLICY_PATH` / `MCP_POLICY_FILE` | Policy JSON path |
| `MCC_LOG_DIR` | Access log directory |
| `MCC_HOST` / `MCP_HOST` | Bind address |
| `MCC_PORT` / `MCP_PORT` | TCP port |
| `MCC_LOCALE` | GUI language: `de` or `en` (fallback if no saved UI locale) |
| `ui_locale` in `config/mcc_ui.json` | Persisted GUI language (`de` / `en`), set via **View → Language** in MCC |

See [`README.md`](README.md) (German project overview) and `README_CURSOR_START_HERE.md` for the maintainer workflow and release gate.

## Reserved policy fields

The following fields may appear in policies migrated from future MCC editions but are **silently ignored by MCC Lite**: `sqlite_mcp`, `gemini_cli`, `github_mcp`, `git`, `at_mention`. Lite only enforces the file-tool surface (`roots`, `permissions`, `blocked`, `tool_registry`, `rate_limit`, `client_blocklist`, `advanced.*`, `honeypot`).

## Origin

MCC emerged from the **EVOKI V5** research project on local AI sovereignty and human–machine trust infrastructure. Where EVOKI explores the full territory — multi-agent systems, constitutional governance, cryptographic provenance — MCC extracts a single primitive as a standalone tool: *what can a machine touch on this disk, and who gets to decide?* MCC is MIT-licensed and developed independently of any EVOKI dependency.

---

*Born in the EVOKI V5 research project · Karlsruhe, 2026*
