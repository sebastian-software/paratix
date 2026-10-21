# Archiv-Härtung abschließen

**Planungsstatus:** Umgesetzt
**Quelle:** `effective-flow plan`
**Empfohlener Workflow:** Bugfix (`effective-flow fix`)
**Nachprüfung:** 21. Oktober 2026, `main` bei `e300a31f`

## Ergebnis

Die Archiv-Härtung wurde mit [PR #233](https://github.com/sebastian-software/paratix/pull/233)
am 2. Oktober 2026 umgesetzt und als `de00be77` in `main` übernommen. Die Nachprüfung bestätigt
die Umsetzung im aktuellen Code und in den Regressionstests. Dieses Dokument hält den Abschluss
im Planarchiv fest.

Die spätere Aufteilung des Archiv-Moduls aus
[PR #231](https://github.com/sebastian-software/paratix/pull/231) erklärt, warum einige Teile
heute in anderen Dateien liegen. Ihr Abschluss ist im
[zugehörigen Refactoring-Plan](2026-10-01-archive-modul-und-containment-flag-aufteilen.md) dokumentiert.

## Abgeschlossener Umfang

| Ergebnis                                                                                                                        | Implementierungsnachweis                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Probe-Fehler werden gezielt behandelt; Verbindungs- und Timeout-Fehler bleiben Fehler.                                          | `archiveProbe.ts`, `ssh.ts`; Regressionen in `archiveProbe.test.ts` und `archive.test.ts`                         |
| Unvollständige Link-Listings werden abgelehnt.                                                                                  | `archiveProbe.ts`, `archiveSymlinkListing.ts`; Unit- und Shell-Tests                                              |
| Fehler einzelner Merge-Batches werden zuverlässig weitergegeben; die Nachprüfung und der Flag-Lebenszyklus bleiben wirksam.     | `archiveStagingMergeScript.ts`; Mock- und Shell-Tests in `archive.test.ts` und `archive.shell.smoke.test.ts`      |
| Member-Pfade und Hardlink-Ziele werden vor dem Entpacken geprüft; legitime Symlink-Ziele bleiben unterstützt.                   | `archiveMemberValidation.ts`; Tar-, Zip- und Link-Regressionen                                                    |
| Der Kernel-Abgleich berücksichtigt gefolgte Links und ordnet Abweichungen dem beurteilten Link zu.                              | `archiveSymlinkResolver.ts`, `archiveLinkValidation.ts`, `archiveContainmentBackstop.ts`; Unit- und Shell-Tests   |
| Eine Member-Liste verwendet einen gemeinsamen Resolver.                                                                         | `archiveLinkAnalysis.ts`; Instanzzähltest in `archiveLinkValidation.test.ts`                                      |
| Die ungenutzte Option `linkTargets` ist aus `validateNoSymlinkPaths` entfernt.                                                  | `archiveDestinationValidation.ts` und dessen Aufrufer                                                             |
| Ein überlaufender Kernel-Abgleich liefert eine verständliche Diagnose.                                                          | `archiveKernelCrossCheckReport.ts`; Tests in `archiveKernelCrossCheck.test.ts`                                    |
| Sonderzeichen und Zeilenumbrüche sind durch Regressionstests abgedeckt; die Modulreferenzen beschreiben das aktuelle Verhalten. | `archiveLinkValidation.test.ts`, `archive.shell.smoke.test.ts`, `docs/module.md`, `packages/paratix/llm-guide.md` |

Alle genannten Quelldateien liegen unter `packages/paratix/src/`, die Tests unter
`packages/paratix/test/modules/`.

## Verifikation

- [x] Code, Aufrufer, Regressionstests und Dokumentation gegen den aktuellen Stand geprüft.
- [x] Die sechs gezielten Archiv-Testsuiten bestehen lokal: 833 Tests bestanden,
      46 plattformabhängig übersprungen.
- [x] `pnpm agent:check` im Archivierungslauf bestanden (Exit-Code 0).
- [x] Der [Integration Check auf dem geprüften Commit](https://github.com/sebastian-software/paratix/actions/runs/38813404718)
      besteht unter Linux, einschließlich Docker-Preflight und 29 Paratix-Integrationstests.

Gezielter lokaler Testlauf:

```sh
pnpm --filter paratix exec vitest run test/modules/archiveProbe.test.ts test/modules/archiveProbe.shell.smoke.test.ts test/modules/archiveLinkValidation.test.ts test/modules/archive.test.ts test/modules/archive.shell.smoke.test.ts test/modules/archiveKernelCrossCheck.test.ts
```

Der zusätzliche lokale Lauf von `pnpm --filter paratix test:integration` am 21. Oktober 2026
erreichte Docker, scheiterte aber beim Laden des Debian-Basisimages an der DNS-Auflösung der
Container-Registry in der lokalen VM. Er ist kein bestandener Integrationstest. Der erfolgreiche
Linux-CI-Lauf oben belegt die Docker-Integration auf demselben Code-Stand.

## Offene Punkte

Keine offenen Implementierungspunkte in diesem Umfang. Die lokale Docker-DNS-Störung betrifft
die erneute Ausführung der Integrationstests, nicht die bereits gemergte Umsetzung.
