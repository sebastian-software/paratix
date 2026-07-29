# 0088: Typecheck für Root-Bootstrap-Scaffold

## Anforderung

Das von `create-paratix` erzeugte `server.ts` soll nicht nur im Standard-Admin-Pfad gegen die lokalen Paratix-Typen kompiliert werden. Auch der Root-Bootstrap-Pfad mit `adminPublicKey` muss durch einen TypeScript-Compile-Guard abgedeckt sein.

## Architekturentscheidungen

- Der vorhandene Typecheck-Aufbau in `packages/create-paratix/test/project-files.test.ts` wurde in einen lokalen Test-Helper verschoben, damit mehrere Scaffold-Varianten dieselbe lokale Paratix-Typauflösung nutzen.
- Der neue Root-Bootstrap-Test erzeugt ein Projekt mit `initialUser: { kind: "root" }` und `TEST_ADMIN_PUBLIC_KEY`, weil Root-Bootstrap ohne Admin-Key bewusst abgelehnt wird.
- Die Prüfung bleibt im bestehenden `writeProjectFiles`-Testbereich und kompiliert weiterhin nur das generierte `server.ts`, damit der Test eng auf die Scaffold-Typabdeckung fokussiert bleibt.

## Betroffene Dateien

| Datei                                                       | Beschreibung                                                                       |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `packages/create-paratix/test/project-files.test.ts`        | Wiederverwendbarer Typecheck-Helper und zusätzlicher Root-Bootstrap-Typecheck-Test |
| `docs/plan/0088-create-paratix-root-bootstrap-typecheck.md` | Dokumentation der Änderung, Validierung und Review-Ergebnisse                      |

## Implementierungsdetails

- `expectGeneratedServerToTypecheck(projectDirectory)` schreibt wie bisher eine temporäre `tsconfig.typecheck.json`.
- Die `paths`-Einträge zeigen auf `packages/paratix/src/index.ts` und `packages/paratix/src/modules/index.ts`, sodass das generierte Projekt gegen lokale Paratix-Typen statt gegen ein veröffentlichtes Paket kompiliert.
- Der bestehende Default-Admin-Typecheck nutzt denselben Helper.
- Ein zusätzlicher Test kompiliert eine root-bootstrap-generierte `server.ts` mit `adminPublicKey`.

## Testergebnisse

- `pnpm --filter create-paratix exec vitest run test/project-files.test.ts` — bestanden, 55 Tests.

## Review-Findings

**Datum:** 2026-05-12
**Reviewer:** keiner

Keine separaten Reviewer gestartet: Die Änderung ist ein fokussierter Test-Coverage-Ausbau ohne Produktivcodeänderung. Die betroffene Stelle wurde im Rahmen der Implementierung und des fokussierten Testlaufs geprüft.
