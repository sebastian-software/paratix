# 0023 — LLM Code Guide

## Anforderung

LLMs wie Claude Code sollen korrekten Paratix-Code (Playbooks und eigene Module) generieren können. Dafür fehlt eine strukturierte Referenz-Datei, die Import-Pfade, API-Signaturen, Patterns und häufige Fehler dokumentiert.

## Architekturentscheidungen

- **Guide im Package**: Der Guide lebt in `packages/paratix/llm-guide.md` und wird mit dem npm-Package ausgeliefert. So finden LLMs die Datei automatisch in `node_modules/paratix/llm-guide.md`. CLAUDE.md und AGENTS.md im Package-Root verweisen darauf. Root-CLAUDE.md und Root-AGENTS.md verweisen ebenfalls (für Entwicklung am Paratix-Projekt selbst).
- **Maschinenlesbare Struktur**: Tabellen für Modul-Signaturen, Code-Blöcke für Beispiele, kurze Sätze statt Prosa. Optimiert für LLM-Parsing.
- **Nur exportierte Module**: Nur die 21 Module die tatsächlich aus `paratix/modules` exportiert werden. `net`, `script` und `compose` sind nicht exportiert und daher nicht dokumentiert.

## Betroffene Dateien

| Aktion     | Datei                           | Beschreibung                                |
| ---------- | ------------------------------- | ------------------------------------------- |
| Erstellt   | `packages/paratix/llm-guide.md` | Hauptreferenz für LLM-Code-Generierung      |
| Erstellt   | `packages/paratix/CLAUDE.md`    | Verweis auf Guide (shipped im npm-Package)  |
| Erstellt   | `packages/paratix/AGENTS.md`    | Verweis auf Guide (shipped im npm-Package)  |
| Bearbeitet | `CLAUDE.md`                     | Verweis auf Package-Guide (für Entwicklung) |
| Bearbeitet | `AGENTS.md`                     | Verweis auf Package-Guide (für Entwicklung) |

## Guide-Inhalt

- **Imports**: Korrekte Import-Pfade (`"paratix"` vs `"paratix/modules"`)
- **Playbook-Struktur**: Vollständiges annotiertes Beispiel
- **Modul-Referenz**: 21 Module mit allen Methoden, Signaturen und Idempotenz-Info
- **Custom Modules**: Vollständiges Beispiel mit check/apply, SshConnection API
- **Template System**: `{{KEY}}` Syntax, Environment-Auflösung
- **Recipes**: Gruppierung, Signale, Verschachtelung
- **Built-in Functions**: assert, when, debug, fail, pause, shellQuote, NEEDS_APPLY
- **Do's and Don'ts**: 22 Einträge (10 Do's, 12 Don'ts)
- **Testing Patterns**: createMockSsh, Vitest-Beispiele

## Review-Findings und Behebung

| ID    | Schweregrad | Problem                                                        | Status                             |
| ----- | ----------- | -------------------------------------------------------------- | ---------------------------------- |
| R-001 | Kritisch    | `net` und `script` als exportiert dokumentiert (sind es nicht) | Behoben                            |
| R-002 | Wichtig     | `service.facts` falsch als always-applies beschrieben          | Behoben                            |
| R-003 | Wichtig     | `import { package }` statt `import { package as pkg }`         | Behoben                            |
| R-004 | Wichtig     | SshConnection API unvollständig (5 Methoden fehlten)           | Behoben                            |
| R-005 | Wichtig     | Testing-Beispiel nutzte `"needs-apply"` statt `NEEDS_APPLY`    | Behoben                            |
| R-006 | Hinweis     | server() Validierung strikter als dokumentiert                 | Behoben                            |
| R-007 | Hinweis     | CLAUDE.md Verweis könnte prominenter sein                      | Nicht umgesetzt                    |
| R-008 | Hinweis     | compose-Modul nicht erwähnt                                    | Nicht umgesetzt (nicht exportiert) |
