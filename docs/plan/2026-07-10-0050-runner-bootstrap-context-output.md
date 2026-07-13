# 0050: Kontextausgabe vor dem SSH-Bootstrap im Runner

## Anforderung

Vor dem eigentlichen SSH-Verbindungsaufbau soll der Paratix-Runner eine knappe, produktivtaugliche Kontextausgabe für jeden Run erzeugen. Diese Ausgabe muss Servername, Zielhost, Ports und Dry-Run-Status enthalten und auch dann sichtbar bleiben, wenn `connect()` oder `probeSudo()` fehlschlagen.

## Architekturentscheidungen

- Die Kontextausgabe wird zentral in `packages/paratix/src/output.ts` über einen kleinen Helper `printRunContext(...)` gekapselt.
- Der Aufruf erfolgt früh in `runPlaybook()` und ausdrücklich vor `connectAndRegister()`, damit der Kontext auch bei Bootstrap-Fehlern sichtbar bleibt.
- Bestehende Header-, Summary- und Fehlerpfade bleiben unverändert; die neue Ausgabe ergänzt den bestehenden Runner-Flow nur um eine frühe Kontextzeile.

## Betroffene Dateien

| Datei                                  | Beschreibung                                                                      |
| -------------------------------------- | --------------------------------------------------------------------------------- |
| `packages/paratix/src/output.ts`       | Neuer Helper für eine knappe Run-Kontextausgabe                                   |
| `packages/paratix/src/runner.ts`       | Früher Aufruf der Kontextausgabe vor dem SSH-Bootstrap                            |
| `packages/paratix/test/runner.test.ts` | Regressionstests für Kontextausgabe bei Connect-/probeSudo-Fehlern und im Dry-Run |

## Implementierungsdetails

- `printRunContext(...)` formatiert eine kompakte Zeile mit:
  - Servername
  - Zielhost
  - Portliste
  - Modus `apply` oder `dry-run`
- `runPlaybook()` ruft die Ausgabe direkt nach Initialisierung von Environment und Shutdown-State auf, bevor `connectAndRegister()` startet.
- Die Regressionstests prüfen:
  - sichtbaren Kontext vor `connect()`-Fehlern
  - sichtbaren Kontext vor `probeSudo()`-Fehlern
  - korrekte `dry-run`-Markierung im frühen Bootstrap-Kontext

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/runner.test.ts`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen internen Review-Findings nach der Umsetzung.
