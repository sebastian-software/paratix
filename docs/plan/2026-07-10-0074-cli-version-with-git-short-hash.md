# 0074: CLI-Version mit Git-Kurz-Hash

## Anforderung

Die Paratix-CLI soll hinter der Paketversion zusätzlich den Kurz-Hash des aktuellen Git-Commits anzeigen, zum Beispiel `v0.4.0-af172d6`.

## Architekturentscheidungen

- Die Anzeige wird als Build-Metadatum erzeugt, nicht zur Laufzeit per `git`-Aufruf.
- Die Paketversion bleibt weiterhin separat als `PACKAGE_VERSION` verfügbar.
- Für Header und `--version` wird ein gemeinsamer Anzeige-String `PACKAGE_DISPLAY_VERSION` verwendet.
- Wenn beim Build kein Git-Hash verfügbar ist, fällt die Anzeige sauber auf die reine Paketversion zurück.

## Betroffene Dateien

| Datei                                  | Beschreibung                                              |
| -------------------------------------- | --------------------------------------------------------- |
| `packages/paratix/tsup.config.ts`      | Build-Define für Paketversion und Git-Kurz-Hash           |
| `packages/paratix/vitest.config.ts`    | Test-Define für denselben Anzeige-String                  |
| `packages/paratix/src/cli.ts`          | Verwendung der Anzeige-Version im Header und in Commander |
| `packages/paratix/test/cli.test.ts`    | Tests für Anzeige-Version und CLI-Header                  |
| `packages/paratix/test/output.test.ts` | Header-Test für Version plus Git-Hash                     |

## Implementierungsdetails

- `tsup.config.ts` liest zusätzlich per `git rev-parse --short HEAD` den Kurz-Hash und bildet daraus `PACKAGE_DISPLAY_VERSION`.
- `vitest.config.ts` nutzt dieselbe Logik, damit Source-Tests und Build-Verhalten konsistent bleiben.
- `cli.ts` verwendet `PACKAGE_DISPLAY_VERSION` für `.version(...)` und `printCliHeader(...)`.
- Die Tests akzeptieren sowohl den Fall mit Hash als auch den Fallback ohne Git-Metadaten.

## Testergebnisse

- `pnpm --filter paratix build`
- `pnpm --filter paratix exec vitest run test/output.test.ts test/cli.test.ts`
- `pnpm agent:check`

## Review-Findings und deren Behebung

- Keine zusätzlichen Findings im Rahmen dieses Features.
