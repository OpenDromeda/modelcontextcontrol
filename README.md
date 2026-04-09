# MCC — Model-Context-Control

> *Who builds a server they can't control?*

**MCC** is the open governance layer for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io).

MCP defines *how* AI systems talk to tools.  
MCC defines *who* can use MCP — and under what conditions.

---

## What MCC Does

- **Policy enforcement** — define what tools are allowed, for which agents, under which conditions
- **Audit logging** — every MCP call is recorded, traceable, reversible
- **Rate limiting** — prevent runaway agents from overloading local resources
- **Blocklists** — block dangerous or untrusted tool patterns by name
- **Transparent failure** — errors are visible, documented, never silent

---

## Why MCC?

The MCP ecosystem is growing fast: 5,800+ servers, 97M+ monthly downloads.  
Most local deployments have no governance layer.

MCC is that governance layer. **Open. Free. Neutral.**

---

## Philosophy

> A system that makes its errors visible and correctable  
> is the only system worth trusting.

---

## Roadmap

- [ ] Core policy engine (JSON-based, hot-reloadable)
- [ ] Audit log (SQLite, immutable append-only)
- [ ] CLI tool (`mcc validate`, `mcc status`, `mcc log`)
- [ ] Docker image for self-hosted deployment
- [ ] Integration guide for common MCP server setups

---

## Domains

| Domain | Purpose |
|--------|---------|
| [modelcontextcontrol.org](https://modelcontextcontrol.org) | Primary — Open Source |
| [modelcontextcontrol.com](https://modelcontextcontrol.com) | International |
| [modelcontextcontrol.io](https://modelcontextcontrol.io) | Tech community |

---

## License

MIT — free for everyone.

---

*Built with [EVOKI V5](https://evolution-ki.com) · Karlsruhe, 2026*
