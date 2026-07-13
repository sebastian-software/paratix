# 0091: Dry-Run-Diff-Ausgabe – Folge-Module

**Planungsstatus:** Umgesetzt
**Empfohlener Workflow:** /build

## Anforderung

In Plan 0090 wurden `file.copy`, `file.template`, `sysctl.set` und `hostname.set` mit Diff-Produktion ausgestattet. Die übrigen ursprünglich anvisierten Module fehlen noch:

- `cron.job` / `cron.absent`
- `timer.scheduled` / `timer.absent`
- `swap.file`
- `net.hosts`
- `quadlet.container`

Dieser Plan ergänzt sie, sodass `paratix apply server.ts --dry-run --diff` für sämtliche Standardpfade einen aussagekräftigen Diff anzeigt.

### Hintergrund

Die öffentliche API ist bereits in Plan 0090 etabliert:

- `ModuleResult.diff?: string`
- `Module._dryRunDiffProducer?: true`
- `RunOptions.diff?: boolean` + `--diff` CLI-Flag
- Diff-Helper `buildUnifiedDiff` / `buildKeyValueDiff` in `packages/paratix/src/modules/diffHelpers.ts`
- Zentraler Marker-Dispatch in `packages/paratix/src/dryRunDispatch.ts`

Die Erweiterung ist **rein additiv**: weitere Module setzen `_dryRunDiffProducer: true` und implementieren `_applyDryRun`. Es werden keine bestehenden Verträge gebrochen.

### Nicht-Ziele

- Keine Änderung an der öffentlichen API. Alles passiert im Modul.
- Keine Diff-Ausgabe im echten Apply-Pfad (gilt weiterhin nur für `--dry-run --diff`).
- Kein strukturierter Diff (JSON o. ä.) – Plaintext-Unified-Diff bleibt das Format.
- Keine Performance-Caps für sehr große Inhalte (siehe `R-0001017` im offenen Review-Report von Plan 0090 – separater Folge-Plan).

## Architekturentscheidungen

### A1: Pro-Modul `_applyDryRun` ohne Mutationen

Jedes Modul liefert in seinem `_applyDryRun`-Hook:

1. Eingangs-Check: ohne SSH → `{ status: "changed" }`.
2. Lese-Operationen ohne Mutationen (kein `writeFile`, `exec` nur mit `silent: true` und `ignoreExitCode: true`).
3. Berechnung des Soll-Inhalts mit denselben Hilfsfunktionen, die der echte `apply()` verwendet.
4. Diff über `buildUnifiedDiff` (mehrzeilige Inhalte) oder `buildKeyValueDiff` (Schlüssel/Wert).
5. Bei Fehlern: `try/catch` mit Fallback `{ status: "changed" }` (kein Diff, aber kein Abbruch).

### A2: Pro-Modul Auswahl von Diff-Strategie

| Modul                                       | Strategie                                                                                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cron.job` (present)                        | Crontab lesen, Marker-Zeile finden, gewünschte Marker+Job-Zeile berechnen, Unified Diff der Cron-Datei.                                                    |
| `cron.job` (absent) + `cron.absent`         | Crontab lesen, Marker finden, gewünschte (gelöschte) Datei berechnen, Unified Diff.                                                                        |
| `timer.scheduled` (present)                 | Service- und Timer-Unit-Datei lesen, mit `paths.serviceContent` / `paths.timerContent` vergleichen. Zwei Diff-Blöcke konkateniert.                         |
| `timer.scheduled` (absent) + `timer.absent` | Vorhandene Unit-Dateien als „-" Block kennzeichnen (Marker-Diff, kein Inhalts-Diff – Mehrwert minimal, einfach).                                           |
| `swap.file` (present)                       | Fstab-Eintrag lesen, mit `expectedFstabLine` vergleichen. Ein Key-Value-artiger Diff.                                                                      |
| `swap.file` (absent)                        | Hinweis-Diff `-${path}` (Swap-Datei wird entfernt).                                                                                                        |
| `net.hosts` (present)                       | `/etc/hosts` lesen, gewünschten Inhalt via vorhandene `buildMergedHostsLine`-Logik berechnen, Unified Diff.                                                |
| `net.hosts` (absent)                        | `/etc/hosts` lesen, ohne Zielzeile berechnen, Unified Diff.                                                                                                |
| `quadlet.container`                         | Quadlet-Unit-Datei lesen, mit `content` vergleichen, Unified Diff. (Falls Flag-Datei fehlt, aber Unit-Inhalt passt: Diff leer, Suffix bleibt „(dry-run)".) |

### A3: Lokale Helper, kein neuer öffentlicher Export

Diff-Bildung passiert in modul-internen Helfern (`buildCronDryRunDiff`, `buildTimerDryRunDiff`, …). Wir exportieren keine neuen Symbole aus dem Public-Modul-Surface – die Helfer bleiben File-local. Damit bleibt die API von `paratix/modules` unverändert.

### A4: Mutex-/Locking-Pfade beim Dry-Run umgehen

Cron- und Net.Hosts-Apply nutzen `withMutexLock`. Im `_applyDryRun` greifen wir die Read-Seite direkt an (kein Lock), weil:

- Wir keine Schreib-Operationen durchführen.
- Concurrent-Apply gegen denselben Host ist außerhalb der Dry-Run-Semantik. Ein veralteter Read-Snapshot ist akzeptabel – der echte Apply würde das Lock anfordern.

### A5: Fehlerfall stets graceful

Jeder Helper wrapt seine SSH-Aufrufe in `try/catch`. Bei Fehlern (SFTP-Hänger, Permission Denied, Symlinks) wird `undefined` (kein Diff) zurückgegeben; der Aufrufer mappt das auf `{ status: "changed" }` ohne `diff`. Damit bleibt das Verhalten konsistent mit Plan 0090.

### A6: `_dryRunDetail` zusätzlich für Sondersituationen

Für `swap.file` (absent), `timer.absent`, `cron.absent` und ähnliche Module, wo der Diff inhaltlich knapp ist, geben wir zusätzlich einen kurzen `_dryRunDetail`-Suffix wie `(absent)`. Damit ist die Statuszeile auch ohne `--diff` informativ.

## Betroffene Dateien

| Datei                                                           | Beschreibung                                                                                      |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/cron.ts`                          | `_dryRunDiffProducer` + `_applyDryRun` für `cron.job` und `cron.absent`.                          |
| `packages/paratix/src/modules/timer.ts`                         | `_dryRunDiffProducer` + `_applyDryRun` für `timer.scheduled` (present/absent) und `timer.absent`. |
| `packages/paratix/src/modules/swap.ts`                          | `_dryRunDiffProducer` + `_applyDryRun` für `swap.file`.                                           |
| `packages/paratix/src/modules/net.ts`                           | `_dryRunDiffProducer` + `_applyDryRun` für `net.hosts`.                                           |
| `packages/paratix/src/modules/quadlet.ts`                       | `_dryRunDiffProducer` + `_applyDryRun` für `quadlet.container`.                                   |
| `packages/paratix/llm-guide.md`                                 | Liste der Diff-fähigen Module ergänzen.                                                           |
| `packages/paratix/README.md`                                    | `--diff`-Beschreibung um die neuen Module erweitern.                                              |
| `packages/paratix/test/modules/cron.test.ts`                    | Neue Test-Sektion „dry-run diff" für cron.job / cron.absent.                                      |
| `packages/paratix/test/modules/timer.test.ts`                   | Neue Test-Sektion für timer.scheduled / timer.absent.                                             |
| `packages/paratix/test/modules/swap.test.ts`                    | Neue Test-Sektion für swap.file.                                                                  |
| `packages/paratix/test/modules/net/` (entsprechende Test-Datei) | Neue Test-Sektion für net.hosts.                                                                  |
| `packages/paratix/test/modules/quadlet.test.ts`                 | Neue Test-Sektion für quadlet.container.                                                          |

## Akzeptanzkriterien

1. `pnpm paratix apply server.ts --dry-run --diff` zeigt für `cron.job`, `cron.absent`, `timer.scheduled`, `timer.absent`, `swap.file`, `net.hosts` und `quadlet.container` einen sinnvollen Diff (oder einen kurzen Marker-Diff, wo Inhalt fehlt).
2. Ohne `--diff` bleibt das Verhalten dieser Module bit-identisch zum Status quo.
3. Module ohne `--diff`-Marker (`apt`, `package`, `service`, `ufw`, `command`, `download`, …) sind unverändert. Kein Modul außerhalb der Liste in A2 wird angefasst.
4. Public API (`paratix`, `paratix/modules`) ist unverändert (kein neuer Export, keine Signature-Änderung).
5. `pnpm agent:check` läuft sauber durch.
6. Mindestens ein Unit-Test pro neuem Diff-Produzenten prüft den erzeugten Diff-Inhalt auf Substrings.

## Validierungsplan

1. **Unit-Tests** pro Modul: Mock-SSH liefert Remote-Inhalt; Test ruft `mod._applyDryRun!(ssh, env)` und assertiert auf erwartete `result.diff`-Substrings.
2. **Backwards-Compat-Test**: einer der Module-Tests prüft, dass `mod.check`/`mod.apply` exakt wie vorher funktionieren (Marker und Hook dürfen die bestehenden Methoden nicht überschreiben).
3. **Pre-Commit-Gate**: `pnpm agent:check`.

## Implementierungsdetails

### Reihenfolge der Phase 2-Schritte

1. `cron.job` + `cron.absent` (gemeinsamer Crontab-Helper).
2. `timer.scheduled` (present) + `timer.scheduled` (absent) + `timer.absent` (gemeinsamer Helper für File-Diff).
3. `net.hosts` (gemeinsamer Hosts-Helper).
4. `swap.file`.
5. `quadlet.container`.

### Diff-Output-Beispiele

```
  ↺  cron.job: backup (root)                          changed  (dry-run)
     │ --- crontab(root)
     │ +++ desired
     │ +# paratix: backup [hash:abc1234]
     │ +0 3 * * * /usr/bin/backup
```

```
  ↺  timer.scheduled: vacuum                          changed  (dry-run)
     │ --- /etc/systemd/system/vacuum.service
     │ +++ desired
     │ -ExecStart=/usr/bin/vacuum --old
     │ +ExecStart=/usr/bin/vacuum --new
```

```
  ↺  net.hosts: 10.0.0.5 db.internal                  changed  (dry-run)
     │ --- /etc/hosts
     │ +++ desired
     │ -10.0.0.5  old.internal
     │ +10.0.0.5  db.internal
```

```
  ↺  swap.file: /swapfile (2G)                        changed  (dry-run)
     │ -/swapfile none swap sw 0 0
     │ +/swapfile none swap sw,pri=10 0 0
```

```
  ↺  quadlet.container: traefik                       changed  (dry-run)
     │ --- /etc/containers/systemd/traefik.container
     │ +++ desired
     │ -Image=docker.io/library/traefik:v3
     │ +Image=docker.io/library/traefik:v3.1
```

### Backwards-Compatibility

- Keine API-Erweiterung; Plan 0090 hat alles bereits eingeführt.
- Module ohne `_applyDryRun`-Hook für Diff verlieren keine Funktion (Markerlogik ist optional).
- Ohne `--diff` werden die neuen Hooks nicht aufgerufen (siehe `shouldExecuteApplyDuringDryRun` in `dryRunDispatch.ts`).

## Offene Fragen

- **Timer absent: Inhalts-Diff oder Marker?** Aktuell nur Marker (Pfad-Liste). Falls der User einen vollen „--- file" Block wünscht, kann das nachgezogen werden. Für den Erstwurf reicht ein knapper Marker, weil die Datei einfach verschwindet.
- **Mutex-frei im Read-Pfad**: dokumentiert in A4. Falls künftig ein paralleler `--diff`-Lauf gleichzeitig mit einem laufenden Apply-Schreiber den Snapshot „erwischt", ist der Diff eventuell veraltet – das ist akzeptiert, weil `--diff` ein Plan-Tool ist, kein Quality Gate.

## Umsetzungsergebnis

| Modul                                       | Status    |
| ------------------------------------------- | --------- |
| `cron.job` (present)                        | Umgesetzt |
| `cron.job` (absent) + `cron.absent`         | Umgesetzt |
| `timer.scheduled` (present)                 | Umgesetzt |
| `timer.scheduled` (absent) + `timer.absent` | Umgesetzt |
| `swap.file` (present + absent)              | Umgesetzt |
| `net.hosts` (present + absent)              | Umgesetzt |
| `quadlet.container`                         | Umgesetzt |

Plan-A6 (zusätzlicher `_dryRunDetail`-Suffix für Sondersituationen) wurde nicht umgesetzt: nicht nötig, weil der gerenderte Diff bzw. die fehlende Diff-Zeile schon klar zeigen, was passiert. Bei Bedarf nachschiebbar, ohne API-Änderung.

### Testergebnisse

- `pnpm agent:check`: erfolgreich.
- Test-Summary nach Umsetzung:
  - `paratix` unit: **3852 passed** (+21 neue Cases im File `test/modules/dry-run-diff-followup.test.ts`)
  - `paratix` distribution: **9 passed**
  - `create-paratix` unit: **256 passed**
  - `create-paratix` distribution: **6 passed**
  - Workspace-Skript-Tests: **34 passed**

## Review-Findings

**Datum:** 2026-06-12
**Reviewer:** orchestrator-internes Review (Phase 6)

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      0 |
| Offen / Nicht umgesetzt |      3 |

**Externer Review-Report:** `.sf-plugin/review/review-report-2026-06-12-plan-0091.md`
