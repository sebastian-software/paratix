# 0085 — Mock-SSH-Fail-Closed-Modul-Tests

## Anforderung

Härte die Mock-SSH-Testabdeckung für sicherheitsrelevante Modul-Tests. Globale permissive Defaults in `file`, `sshd`, `download` und `cron` sollen entfernt oder durch präzise lokale Stubs beziehungsweise Allowlist-Einträge ersetzt werden. Unstubbed Commands müssen standardmäßig fehlschlagen.

## Architekturentscheidungen

### Fail-Closed bleibt Helper-Default

`createMockSsh()` bleibt ohne Optionen strikt: nicht explizit gestubbte `exec`, `output`, `test` und Side-Effect-Aufrufe werfen weiterhin Fehler. Die Legacy-Fallbacks (`defaultExecResult`, `defaultOutputResult`, `defaultTestResult`, `strict: false`) bleiben nur als explizite Testoptionen verfügbar.

### Präzise Response-Stubs statt globaler Defaults

Der Mock-SSH-Helper unterstützt jetzt `responseStubs`: Regex- oder String-basierte Stubs, die nach exakten Response-Map-Einträgen und vor Fallbacks greifen. Dadurch können Modul-Tests wiederkehrende, erwartete Befehlsfamilien lokal erlauben, ohne beliebige unbekannte Commands erfolgreich durchzulassen.

### Modul-Test-Härtung

- `file.test.ts`: globale `defaultExecResult`, `defaultOutputResult` und `defaultTestResult` entfernt; ersetzt durch lokale Stubs für bekannte File-Metadaten- und File-Operationen sowie Side-Effect-Allowlists für erwartete Uploads/Writes.
- `sshd.test.ts`: globaler `defaultExecResult` entfernt; ersetzt durch lokale Stubs für die erwarteten `sshd -t`, `systemctl`- und temporären Dry-Run-Aufräum-Kommandos.
- `cron.test.ts`: globaler `defaultExecResult` entfernt; ersetzt durch lokale Stubs für Crontab-Schreibbefehle.
- `download.test.ts`: globale Exec/Output/Test-Defaults entfernt; ersetzt durch lokale Stubs für erwartete Download-, Metadata-Heal- und Flag-Kommandos.

## Betroffene Dateien

| Datei                                                 | Aktion   |
| ----------------------------------------------------- | -------- |
| `packages/paratix/test/helpers/mockSsh.ts`            | Geändert |
| `packages/paratix/test/helpers/mockSsh.test.ts`       | Geändert |
| `packages/paratix/test/modules/file.test.ts`          | Geändert |
| `packages/paratix/test/modules/sshd.test.ts`          | Geändert |
| `packages/paratix/test/modules/cron.test.ts`          | Geändert |
| `packages/paratix/test/modules/download.test.ts`      | Geändert |
| `docs/plan/0085-mock-ssh-fail-closed-module-tests.md` | Neu      |

## Implementierungsdetails

- `MockResponseStub` ergänzt: `{ command: string | RegExp; result: Partial<ExecResult> }`
- `getMockResponse()` prüft zuerst exakte Response-Map-Einträge, dann `responseStubs`, danach die bestehenden expliziten Defaults beziehungsweise Allowlists.
- Helper-Test ergänzt, der zeigt: ein präziser Stub erlaubt nur den passenden `stat`-Befehl, ein anderes `cat` bleibt fail-closed.
- In den Modul-Tests wurden permissive Defaults durch konkrete lokale Stubs ersetzt, damit neue unerwartete Remote-Befehle wieder Testfehler erzeugen.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/helpers/mockSsh.test.ts test/modules/file.test.ts test/modules/sshd.test.ts test/modules/cron.test.ts test/modules/download.test.ts` — 5 Dateien, 348 Tests bestanden
- `pnpm agent:check` — bestanden
  - Lint: bestanden
  - Format-Check: bestanden
  - Typecheck: bestanden
  - Build: bestanden
  - Tests: bestanden (`create-paratix`: 140 Tests; `paratix` Unit: 2303 Tests; Distribution: 1 Test)

## Review-Findings

**Datum:** 2026-05-04
**Reviewer:** keiner

Kein separater Reviewer gestartet, weil die Änderung ausschließlich Test-Härtung und Test-Helper-Verhalten betrifft und vollständig durch gezielte Regressionstests sowie `pnpm agent:check` validiert wurde.
