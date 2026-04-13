# MCC — Modell-Kontext-Steuerung

**Website (Community):** [https://modelcontextcontrol.io/](https://modelcontextcontrol.io/)  
**Quellcode:** [https://github.com/EvolutionKi/modelcontextcontrol](https://github.com/EvolutionKi/modelcontextcontrol)

> Wer baut schon einen Server, den er nicht kontrollieren kann?

**MCC** ist die offene Governance-Schicht für das **Model Context Protocol (MCP)**.

- **MCP** definiert, wie KI-Systeme mit Werkzeugen kommunizieren.  
- **MCC** definiert, wer MCP nutzen darf — und unter welchen Bedingungen.

## Was MCC tut

- **Richtliniendurchsetzung** — Festlegung, welche Instrumente für welche Akteure unter welchen Bedingungen zulässig sind  
- **Audit-Protokollierung** — jeder MCP-Aufruf wird aufgezeichnet, ist nachvollziehbar und reversibel  
- **Ratenbegrenzung** — Verhinderung der Überlastung lokaler Ressourcen durch außer Kontrolle geratene Agenten  
- **Blocklisten** — gefährliche oder nicht vertrauenswürdige Werkzeugmuster anhand ihres Namens blockieren  
- **Transparente Fehler** — Fehler sind sichtbar, dokumentiert, niemals verschwiegen  

## Warum MCC?

Das MCP-Ökosystem wächst rasant: über 5.800 Server, über 97 Millionen Downloads monatlich.  
Die meisten lokalen Installationen verfügen über **keine** Governance-Ebene.

**MCC ist diese Governance-Ebene.** Offen. Frei. Neutral.

## Philosophie

> Ein System, das seine Fehler sichtbar und korrigierbar macht,  
> ist das einzige System, dem man vertrauen kann.

## Roadmap

- Kern-Richtlinien-Engine (JSON-basiert, Hot-Reloading möglich)  
- Audit-Protokoll (SQLite, unveränderlich, nur Anhängen)  
- CLI-Tool (`mcc validate`, `mcc status`, `mcc log`)  
- Docker-Image für die selbstgehostete Bereitstellung  
- Integrationsleitfaden für gängige MCP-Serverkonfigurationen  

## Domains

| Domain | Zweck |
|--------|--------|
| [modelcontextcontrol.org](https://modelcontextcontrol.org/) | Primär — Open Source |
| [modelcontextcontrol.com](https://modelcontextcontrol.com/) | International |
| [modelcontextcontrol.io](https://modelcontextcontrol.io/) | Technologie-Community |

## Lizenz

**MIT** — kostenlos für alle.

---

**Dieses Repository** enthält **MCC Lite**: die lokale Referenzimplementierung mit Guardian-Oberfläche, Policy-JSON und MCP-Server-Oberfläche für Datei-Werkzeuge. Technische Details und Release-Gate: [`README_CURSOR_START_HERE.md`](README_CURSOR_START_HERE.md) · englische Kurzfassung: [`README_EN.md`](README_EN.md).

## Reservierte Policy-Felder

Folgende Felder können in Policies aus zukünftigen MCC-Editionen vorkommen, werden von **MCC Lite aber stillschweigend ignoriert**: `sqlite_mcp`, `gemini_cli`, `github_mcp`, `git`, `at_mention`. Lite setzt nur die Datei-Tool-Schicht durch (`roots`, `permissions`, `blocked`, `tool_registry`, `rate_limit`, `client_blocklist`, `advanced.*`, `honeypot`).

## Herkunft

MCC entstand aus dem Forschungsprojekt **EVOKI V5** über lokale KI-Souveränität und Mensch-Maschine-Vertrauensinfrastruktur. Während EVOKI das gesamte Terrain erkundet — Multi-Agenten-Systeme, konstitutionelle Governance, kryptografische Provenienz — extrahiert MCC ein einzelnes Primitiv als eigenständiges Werkzeug: *was darf eine Maschine auf dieser Festplatte berühren, und wer entscheidet das?* MCC ist MIT-lizenziert und wird unabhängig von jeder EVOKI-Abhängigkeit entwickelt.

---

*Entstanden im Forschungsprojekt EVOKI V5 · Karlsruhe, 2026*
