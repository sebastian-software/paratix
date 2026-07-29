# 0059: create-paratix Host Prompt and Template Injection

## Anforderung

`create-paratix` soll beim Scaffold den Zielhost direkt abfragen oder per CLI entgegennehmen und ihn sofort in das generierte `server.ts` schreiben.

## Architekturentscheidungen

- Der Host wird Teil des expliziten Scaffold-Vertrags und nicht länger als statischer Platzhalter in `templates.ts` belassen.
- Neben dem interaktiven Prompt gibt es einen nicht-interaktiven CLI-Pfad über `--host <domain-or-ip>`.
- Die Host-Validierung bleibt bewusst pragmatisch: nicht leer, getrimmt, keine Leerzeichen. DNS- oder Netzwerkvalidierung findet im Scaffold nicht statt.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                |
| -------------------------------------------- | ----------------------------------------------------------- |
| `packages/create-paratix/src/index.ts`       | CLI-Parsing, Host-Prompt und Host-Validierung ergänzt       |
| `packages/create-paratix/src/templates.ts`   | `server.ts`-Template nimmt den Host als Parameter           |
| `packages/create-paratix/test/index.test.ts` | Tests für Host-Prompt, CLI-Flag und Template-Inhalt ergänzt |
| `packages/create-paratix/README.md`          | Neuer Host-Flow interaktiv und per CLI dokumentiert         |

## Implementierungsdetails

- Neuer CLI-Parameter `--host <domain-or-ip>`.
- Interaktive Frage `Server host (domain or IP):`.
- `writeProjectFiles()` und `createServerTemplate()` bekommen den Host explizit durchgereicht.
- Default bleibt `1.2.3.4`, wenn intern ohne Host-Option getestet oder aufgerufen wird.

## Testergebnisse

- `pnpm --filter create-paratix test`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen Findings aus der Implementierung.
