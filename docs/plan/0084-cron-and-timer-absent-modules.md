# 0084 — Cron- und Timer-Absent-Module

## Anforderung

Dedizierte „uninstall"-Methoden für die beiden Scheduling-Module — `cron.absent(user, name)` und `timer.absent(name)` — gemäß Paratix-Konvention (`file.absent`, `group.absent`, `mount.absent`, `package.absent`, `user.absent`).

## API

```typescript
cron.absent(user: string, name: string): Module
timer.absent(name: string): Module
```

## Architekturentscheidungen

### Naming `absent` statt `uninstall`

Paratix-Konvention für „nicht-vorhanden": `<module>.absent(...)`. Die etablierte API-Symmetrie schlägt das vom User vorgeschlagene `uninstall` — sechs andere Module nutzen das Muster bereits.

### Backward-Compat

`cron.job(..., { state: "absent" })` und `timer.scheduled(..., { state: "absent" })` bleiben funktional unverändert. Die neuen `absent`-Methoden sind die idiomatische Alternative ohne Dummy-Werte für `job`, `exec` oder `onCalendar`.

### Implementierungs-Strategie

- **`cron.absent`**: eigene `check`/`apply`-Logik (analog `user.absent`). Marker-Logik (entferne Marker + Folgezeile, oder `crontab -r` wenn Crontab leer wird). Refactoring: `assertCronName` als Helper extrahiert, von beiden Methoden genutzt.
- **`timer.absent`**: Wrapper über die vorhandenen internen Helper `applyAbsent`/`checkAbsent`/`buildTimerLocations`. Keine Content-Render-Logik nötig. Refactoring: `assertTimerName` extrahiert.

### Idempotenz-Verbesserung im `applyAbsent`-Helper

Der existierende `applyAbsent`-Helper (genutzt von beiden `timer.absent` und `timer.scheduled` mit `state: "absent"`) prüft jetzt zu Beginn, ob beide Unit-Dateien fehlen. Falls ja → `{ status: "ok" }` ohne weitere Operationen. Vermeidet einen unnötigen `daemon-reload` und sorgt für saubere Idempotenz auch bei direktem Apply-Aufruf außerhalb der Standard-Pipeline.

### Modulnamen in Fehlertexten

`applyAbsent` nimmt jetzt einen Kontext mit `module: "timer.absent" | "timer.scheduled"`, damit Fehlermeldungen den korrekten Modulnamen tragen.

## Betroffene Dateien

| Datei                                             | Aktion   |
| ------------------------------------------------- | -------- |
| `packages/paratix/src/modules/cron.ts`            | Geändert |
| `packages/paratix/src/modules/timer.ts`           | Geändert |
| `packages/paratix/test/modules/cron.test.ts`      | Geändert |
| `packages/paratix/test/modules/timer.test.ts`     | Geändert |
| `packages/paratix/llm-guide.md`                   | Geändert |
| `docs/plan/0084-cron-and-timer-absent-modules.md` | Neu      |

## Implementierungsdetails

- **cron.absent**: `apply` liest Crontab → wenn Marker fehlt: `{status: "ok"}` ohne Schreiben → sonst `splice(markerIndex, 2)` und `writeCrontab` (welcher `crontab -r` macht, falls leer)
- **timer.absent**: minimaler Wrapper. Pfade via `buildTimerLocations(name)`, `apply` ruft `applyAbsent(ssh, {locations, module: "timer.absent", name})`
- `assertCronName` und `assertTimerName` verhindern Code-Duplikation der Validierung

## Testergebnisse

90 Tests in `cron.test.ts` und `timer.test.ts`, alle bestanden:

- `cron.absent` (11 neue Tests): check ok/needs-apply, apply removes/keeps untouched/empties crontab, name validation, multi-marker handling, trailing marker without job line
- `timer.absent` (12 neue Tests): check, apply happy path, apply tolerates missing unit, apply failure paths (rm, daemon-reload), idempotent no-op, ssh-null, name format, name validation, error message contains correct module name

## Review-Findings und Behebung

Internes nodejs-reviewer-Review hat 9 Findings geliefert. Behoben:

| Finding                                             | Bereich        | Behebung                                                         |
| --------------------------------------------------- | -------------- | ---------------------------------------------------------------- |
| `timer.absent.apply` immer `changed`                | Idempotenz     | `applyAbsent` returnt `ok` wenn beide Files fehlen               |
| Fehlertexte zeigen `timer.scheduled` bei `absent`   | API-Konsistenz | `applyAbsent` bekommt Kontext mit Modulnamen                     |
| JSDoc-Pattern stimmt nicht mit Code überein         | Doku           | JSDoc auf `^[\w\-]+$` korrigiert                                 |
| JSDoc „last managed entry"                          | Doku           | präzisiert zu „when the crontab becomes empty after the removal" |
| Fehlende Tests: trailing marker, daemon-reload-fail | Test-Coverage  | beide Edge-Cases ergänzt                                         |
| Zusätzlicher Test: error message references module  | Test-Coverage  | Test ergänzt                                                     |

Bewusst nicht umgesetzt:

- Restriktiveres `name`-Pattern für `cron.absent` (Reviewer F1): `cron.job` ist permissiv, Konsistenz schlägt zusätzliche Validierung
- Equivalence-Test `cron.absent` vs. `cron.job(state="absent")` (Reviewer F8): Verhalten ist über getrennte Tests bereits spezifiziert
- Mehr Edge-Case-Tests für mehrere Marker (Reviewer F4): durch existierenden „only touches targeted marker" abgedeckt

## Validierung

- `pnpm lint` — clean
- `pnpm format:check` — clean
- `pnpm typecheck` — clean
- 90 Tests in den geänderten Test-Dateien grün; insgesamt 1725/1726 (CLI-Versionsstring-Test ist wieder vorbestehend, ohne Bezug)
