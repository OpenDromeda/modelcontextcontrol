MCC – HILFE
===========
Stand: MCC (OAuth/GitHub, Bearer optional, Keystore, erweiterte Überwachung)

DISCLAIMER
----------
Diese Hilfe wird nach bestem Wissen aus Betrieb und Dokumentation gepflegt.
Es besteht keine Garantie und kein Anspruch auf Vollständigkeit oder Aktualität.
Technische Details (FastMCP, Claude, GitHub) können sich unterscheiden; prüfen Sie
bei Bedarf die jeweilige Herstellerdokumentation.

ÜBERBLICK
---------
Der Guardian startet den FastMCP-Server (Standard-Port 8766). Zugriffe werden
protokolliert (tägliche Log-Datei mcp_access_YYYYMMDD.jsonl).
Typischer Weg für Claude: OAuth über GitHub (Client-ID/Secret im Keystore speicherbar).
Alternativ: Bearer-Token pro Client (Codex/ChatGPT) – ebenfalls im Keystore.
Ausführlicher Datenfluss: siehe Anhang unten.

1) ERSTER START / MASTER-PASSWORT
------------------------------------
• Beim ersten Start Master-Passwort wählen (min. 12 Zeichen).
• Ohne korrektes Passwort startet der MCP-Server nicht.
• Passwort vergessen: nur Reset über 'Keystore zurücksetzen' (alle Keys inkl. OAuth weg).

2) SCHNELLSTART
---------------
• Beim Öffnen der App startet der MCP-Server nicht automatisch – erst „Stack starten"
  (inkl. Selbsttest nach erfolgreichem Start).
• Auth-Modus 'github' (Standard): GitHub OAuth App anlegen, Client-ID/Secret im Tab
  Auth/Connector eintragen und optional 'OAuth im Keystore speichern'.
• Ohne Client-ID/Secret startet „Stack starten" den MCP-Server nicht; der Selbsttest
  läuft erst nach erfolgreichem Start über „Stack starten".
• Nach Änderung von Secret oder Keystore: MCP-Server stoppen und neu starten.
• Alternative Auth-Modus 'bearer': Keys unter 'Bearer Keys' generieren,
  Token im Connector (Authorization: Bearer …).
• Stack starten.
• Öffentliche MCP-URL (Beispiel): https://mcp.evolution-ki.com/mcp

3) POLICY
---------
• read_only als Standard; read_write nur bei Bedarf.
• Optional permissions.agents.<name>.write_allow_paths in der JSON-Datei.
• Der Server lädt die Policy bei jedem Request neu.

4) BLOCKLIST / RATE-LIMIT
-------------------------
• Geblockte IPs: config/blocked_ips.json (Tab Blocklist).
• Rate-Limit und client_blocklist in mcp_policy.json konfigurierbar.

5) MONITORING
-------------
• Statusleiste: Uptime, Upload-Session, Aktivitätsampel.
• Verdächtige Zugriffe: Score ≥ 25.

6) TECHNISCHE HINWEISE
---------------------
• Für reproduzierbares OAuth-Verhalten eine aktuelle FastMCP-Version gemäß
  requirements.txt verwenden (Version dort eingegrenzt).

7) HINTERGRUND & PROJEKT
------------------------
• Manifest, Werte, Ziel: https://evolution-ki.com
• Guardian, Kosten, Live-Log: https://evolution-ki.com/projekt

8) SICHERHEITS-SPEZIFIKATION
============================
Diese Spezifikation beschreibt alle Sicherheitsmaßnahmen des Guardian.
Ziel: Du sollst nachvollziehen können, was der Guardian tut und warum –
ohne Programmierkenntnisse. Der Quellcode ist quelloffen und prüfbar.

--- BESTEHENDE SCHUTZMECHANISMEN ---

a) Verschlüsselter Keystore (PBKDF2 + Fernet)
   Was: Alle Zugangsdaten (OAuth-Secrets, Bearer-Keys) werden verschlüsselt
   auf der Festplatte gespeichert – nicht im Klartext.
   Warum: Selbst wenn jemand Zugriff auf deinen PC bekommt, kann er ohne
   das Master-Passwort die gespeicherten Schlüssel nicht lesen.
   Wie: Dein Passwort wird 480.000-mal durch eine mathematische Funktion
   geschickt (PBKDF2), bevor es als Schlüssel dient. Das macht das
   automatisierte Durchprobieren von Passwörtern extrem langsam.

b) Policy-basierter Dateizugriff
   Was: Du bestimmst über eine Konfigurationsdatei (mcp_policy.json),
   welche Ordner gelesen und welche beschrieben werden dürfen.
   Warum: 'Du bestimmst, was geteilt wird' – dieser Grundsatz wird hier
   technisch umgesetzt. Sensible Bereiche (.ssh, .env, Schlüsseldateien)
   sind standardmäßig gesperrt.
   Wie: Jeder Dateizugriff wird gegen die Policy geprüft. Verbotene Ordner,
   Dateiendungen und Namens-Muster werden erkannt und blockiert.

c) Authentifizierung (OAuth / Bearer)
   Was: Nur autorisierte Clients dürfen den MCP-Server nutzen.
   Warum: Ohne Anmeldung könnte jeder, der die URL kennt, auf deine Dateien
   zugreifen. OAuth über GitHub stellt sicher, dass nur du (oder von dir
   autorisierte Personen) Zugang haben.
   Wie: Bei OAuth wird die Identität über GitHub bestätigt. Bei Bearer-Tokens
   wird ein geheimer Schlüssel verglichen – timing-sicher, damit ein Angreifer
   aus der Antwortzeit nicht ableiten kann, wie viele Zeichen richtig waren.

d) IP-Blocklist und Rate-Limiting
   Was: Adressen mit zu vielen fehlgeschlagenen Versuchen werden automatisch
   gesperrt. Maximal 30 Anfragen pro Minute pro Adresse.
   Warum: Schützt vor automatisierten Angriffen (Brute-Force), bei denen
   Tausende Passwörter oder Schlüssel pro Sekunde durchprobiert werden.
   Wie: Der Zähler für fehlgeschlagene Versuche überlebt Server-Neustarts
   (persistente Speicherung). Gesperrte IPs in config/blocked_ips.json.

e) Tägliche Access-Logs
   Was: Jeder Zugriff wird mit Zeitstempel, Tool, Client-IP, Ergebnis und
   Pfad in einer täglichen Protokolldatei festgehalten.
   Warum: Vollständige Transparenz – du kannst jederzeit nachsehen, wer wann
   was gemacht hat. Das ist die Grundlage für 'prüfbar'.
   Wie: JSONL-Dateien unter logs/mcp_access_YYYYMMDD.jsonl. Maschinenlesbar
   und menschenlesbar. Standardmäßig unbegrenzte Aufbewahrung.

f) Verdachts-Scoring
   Was: Zugriffe werden anhand von Mustern bewertet. Ab einem Score von 25
   erscheinen sie im Bereich 'Verdächtige Zugriffe'.
   Warum: Nicht jeder ungewöhnliche Zugriff ist ein Angriff, aber die
   Auffälligkeiten sollen sichtbar sein – für deine Einschätzung.
   Wie: Punkte für fehlende Client-ID, fehlenden User-Agent, sensible Pfade
   im Zugriff, hohe Anfragerate oder abgelehnte Zugriffe.

g) Cloudflare-Tunnel
   Was: Der MCP-Server ist nicht direkt aus dem Internet erreichbar.
   Der Zugang läuft über einen verschlüsselten Tunnel von Cloudflare.
   Warum: Kein offener Port auf deinem Rechner nötig. Selbst wenn dein
   Router Schwachstellen hat, kommt niemand direkt zum Server.
   Wie: Der Tunnel wird als Windows-Dienst betrieben und verbindet sich
   ausgehend mit Cloudflare. Eingehende Anfragen werden über die
   öffentliche URL (z. B. mcp.evolution-ki.com) durch den Tunnel geleitet.

--- NEUE SCHUTZMECHANISMEN (Security Hardening) ---

h) Implicit-Deny für Schreibzugriffe
   Was: Im Schreibmodus (read_write) sind nur Pfade beschreibbar, die
   explizit in write_allow_paths stehen. Alles andere wird abgelehnt.
   Warum: Wenn die Positivliste leer oder falsch konfiguriert ist, darf
   trotzdem nichts geschrieben werden – Sicherheit durch Vorsicht.

i) Kontrollfluss-Sicherung
   Was: Nach jeder Zugriffsverletzung bricht der Server die Verarbeitung
   sofort und vollständig ab.
   Warum: Selbst wenn eine interne Fehlermeldung nicht korrekt ausgelöst
   wird, läuft der Code nicht einfach weiter. Lieber Abbruch als Risiko.

j) Kindpfad-Prüfung beim Löschen
   Was: Bevor ein Ordner rekursiv gelöscht wird, prüft der Server jeden
   darin enthaltenen Dateipfad gegen die Blocklisten.
   Warum: Verhindert, dass geschützte Dateien (.env, Schlüssel) durch das
   Löschen eines übergeordneten Ordners versehentlich mitgelöscht werden.

k) Schreibgrößen-Limit
   Was: Ein einzelner Schreibvorgang darf maximal 5 MB umfassen (einstellbar).
   Warum: Schützt vor dem Füllen der Festplatte durch einen bösartigen oder
   fehlerhaften Client. Normale Textdateien sind weit unter diesem Limit.

l) Elternverzeichnis-Audit
   Was: Wenn beim Schreiben einer Datei automatisch Unterordner erstellt
   werden, wird das im Zugriffsprotokoll vermerkt.
   Warum: Transparenz – du siehst nicht nur welche Datei geschrieben wurde,
   sondern auch ob dabei Verzeichnisse entstanden sind.

m) Passwort-Hygiene
   Was: Das Master-Passwort wird nach dem Entsperren aus dem Arbeitsspeicher
   entfernt. Bei Bedarf (z.B. neuen Key generieren) wird es kurz abgefragt.
   Warum: Reduziert das Zeitfenster, in dem ein Angreifer mit Zugriff auf
   den Arbeitsspeicher das Passwort auslesen könnte.

n) Secrets ohne dauerhafte Umgebungsvariablen
   Was: Geheimnisse (OAuth-Secret, Bearer-Keys) schreibt der Guardian in eine
   kurzlebige Datei (Pfad nur in MCP_SECRETS_FILE); der MCP-Prozess liest sie
   beim Start und löscht sie danach. Kein MCP_OAUTH_CLIENT_SECRET in der
   dauerhaften Umgebung.
   Warum: Dauerhafte Umgebungsvariablen können unter Windows von anderen
   Programmen ausgelesen werden; stdin war auf manchen Setups unzuverlässig.

o) Persistentes Rate-Limiting
   Was: Der Zähler fehlgeschlagener Anmeldeversuche wird auf der Festplatte
   gespeichert und überlebt Server-Neustarts.
   Warum: Ein Angreifer kann nicht einfach durch Auslösen eines Neustarts
   seinen Fehlversuchs-Zähler zurücksetzen.

p) Pfad-Normalisierung
   Was: Windows erlaubt verschiedene Schreibweisen für denselben Pfad
   (z.B. Kurznamen wie PROGRA~1, versteckte Datenströme, Netzwerkpfade).
   Der Guardian erkennt und blockiert solche Tricks.
   Warum: Verhindert, dass Blocklisten durch alternative Pfadformate
   umgangen werden.

q) Priorisierte Dateisuche
   Was: Bei einer Dateisuche werden zuerst die aktiven Projektordner
   durchsucht, dann erst der Rest (Archiv, Backups).
   Warum: Liefert relevantere Ergebnisse und verhindert, dass der Server
   minutenlang durch Hunderttausende alter Dateien sucht.

Quellcode und Werte: https://evolution-ki.com
Kostenlos, quelloffen, prüfbar.

ANHANG – Datenfluss (für Interessierte)
=======================================
ASCII-Überblick (vereinfacht; Pfade können je nach Setup variieren):

  [ Dein PC – Guardian / FastMCP / Logs / Policy lokal ]
           |
           |  cloudflared (Tunnel, ausgehende Verbindung)
           v
  [ Öffentliche HTTPS-URL (Cloudflare) ]
           |
           |  Claude.ai / MCP-Connector (Browser oder Client)
           v
  [ GitHub – Anmeldung / OAuth-Zustimmung ]
           |
           |  Token-Tausch: nur zwischen MCP-Server-Prozess und GitHub
           |  (Client-ID + Client-Secret dabei, nicht im Klartext in .env)
           v
  [ MCP auf localhost:8766 – Requests, Policy, Access-Log lokal ]

Legende (was wohin fließt):
• GitHub-Passwort / Login: nur zwischen dir und GitHub (Browser/IdP), nicht an den MCP.
• Client-Secret: nur im autorisierten Token-Austausch Server↔GitHub; im Keystore verschlüsselt.
• Policy, Blocklisten, Access-Logs: lokal unter config/ und logs/.
