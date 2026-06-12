# 0092: Flag-Lock-Diagnose und Shell-Pattern-Smoketests

**Planungsstatus:** Umgesetzt
**Quelle:** /plan
**Empfohlener Workflow:** Refactoring (`/refactor`)

## Anforderung

Issue 35 hat zwei strukturelle Schwachstellen offengelegt, die der reine Bugfix in Commit `1fb3cf5b` bewusst nicht angefasst hat, weil er minimal bleiben sollte. Beide gehören in einen Refactoring-Lauf, weil sie kein Nutzerverhalten ändern, sondern die Diagnose- und Test-Architektur robuster machen:

1. **Diagnose-Suffix bei Flag-Lock-Fehlern.**
   `writeFlagLockHolderMarker` (`packages/paratix/src/modules/flagLock.ts:110-178`) liest den Holder-Token über `ssh.output("awk … ")` mit anschließendem `.catch(() => "")`. Jeder Fehler (kaputter `awk`-Aufruf, fehlende Datei, Permission-Denied, IO-Error) wird stumm in einen leeren Token übersetzt; die spätere Fehlermeldung sagt lediglich `[moduleHelpers] flag lock holder marker for <name> is empty after write`. Bei Issue 35 hat das die Diagnose von 30 Sekunden auf 30 Minuten gestreckt: der `EUSAGE`-Exit-Code von `awk` war im Log nirgendwo zu sehen.

2. **Pattern-Tests gegen das eigene Format statt gegen das echte Shell-Verhalten.**
   Die Mock-SSH-Pattern in `packages/paratix/test/helpers/mockSshFlagLock.ts` und die direkten Command-String-Erwartungen in `packages/paratix/test/modules/{cron,apt,moduleHelpers,sshd/05-*,sshd/06-*}.test.ts` prüfen exakt dieselben Strings, die der Production-Code emittiert. Wenn der Production-Code einen Bug einbaut (`awk … --` statt `awk …`, Quote-Mismatch, fehlende Path-Escapes), erwartet der Mock denselben Bug und alle Tests bleiben grün. Issue 35 ist genau so durchgekommen.

### Hintergrund

- Issue 35 (`fix: drop --  from flag-lock awk readbacks`, Commit `1fb3cf5b`): `awk … --` wurde von beiden Mock und Production gleich falsch behandelt. Erst der Live-Run auf einer Ubuntu-Box hat den Bug gezeigt.
- Beim Publish-Bug (Commit `07ceb0e9`) war es das gleiche Muster: `pnpm --dir <path> publish …` war im Production-Code falsch, der Test hat exakt diesen falschen Aufruf als Erwartung eingebrannt.
- Beide Fälle sind keine Bugs „im Test", sondern Hinweise darauf, dass die Test-Strategie für Shell-Commands keine echte Verifikation gegen ein Shell darstellt.

### Nicht-Ziele

- Kein neues Modul, kein neuer CLI-Flag, kein neues User-Verhalten.
- Keine Änderung der Lock-Acquire-Semantik. Verhalten beim Erfolg bleibt bit-identisch.
- Kein vollständiger Umbau der Mock-Architektur. Smoketests werden additiv eingeführt; bestehende Mock-String-Tests bleiben erhalten (sie schützen weiterhin gegen Quoting-Regressionen im Aufrufer-Pfad).

## Architekturentscheidungen

### A1: `ssh.exec` statt `ssh.output` für den Holder-Readback

Aktuell verschluckt `ssh.output(…).then(…).catch(() => "")` jeden Fehler. Der Ersatz nutzt `ssh.exec(command, { ignoreExitCode: true, silent: true })` und liefert sowohl `code` als auch `stderr` zurück. Die strukturierte Fehlermeldung im Empty-Token-Pfad bekommt damit Exit-Code und Stderr beigemischt — und zwar bevorzugt über den existierenden `failedCommand(...)`-Pfad statt über `failed(message)`, weil `failedCommand` Stderr automatisch durch `maskRegisteredSecrets` schickt.

Begründung:

- Konsistenz mit dem Printf-Pfad oberhalb, der ebenfalls `failedCommand(...)` nutzt.
- Stderr läuft automatisch durch die Secret-Maskierung (R-0000041), was eine eigene Lösung gar nicht erst nötig macht.
- Die Mock-SSH-Klasse unterstützt `exec` mit `ignoreExitCode` bereits ohne Anpassung.

### A2: Empty-Token bleibt eigener Failure-Pfad, aber mit Aufruf-Kontext

Wenn der `exec`-Call mit `code === 0` und nicht-leerer Stdout zurückkommt, der getrimmte Token aber leer ist (Marker-Datei ist real leer), bleibt das Verhalten wie heute: lock-Verzeichnis aufräumen, `failed(...)` zurückgeben. Die Fehlermeldung benennt die Ursache explizit als „marker file readable but empty" statt der heutigen mehrdeutigen „empty after write". Damit lässt sich das Symptom „Datei wirklich leer" von „awk gescheitert" auseinanderhalten.

### A3: Smoketest-Datei statt vollständige Mock-Ablösung

Neu: `packages/paratix/test/modules/flagLock.shell.smoke.test.ts`. Die Datei führt eine kleine Auswahl von Production-Commands gegen ein echtes `/bin/sh` aus, in einem `mkdtemp`-Verzeichnis. Sie prüft:

- `writeFlagLockHolderMarker`: printf-Statement schreibt eine Datei mit dem erwarteten Token-Format; das daraus generierte awk-Readback liest sie zurück.
- `releaseFlagLock`: das komposierte Release-Statement entfernt Marker + Lock-Verzeichnis.
- `tryReclaimStaleFlagLock`: der Reclaim-Probe entfernt einen alten Lock und lässt einen frischen unberührt.

Begründung:

- Bezahlbar (eine Datei, wenige Sekunden Laufzeit, kein SSH).
- Fängt awk-/quoting-/escape-Bugs, weil das echte Shell die Wahrheit ist, nicht ein selbst gepflegtes Pattern.
- Ergänzt die bestehenden Mock-Pattern-Tests, ersetzt sie nicht: Mock-Patterns prüfen weiterhin die Aufrufer-Schicht (z. B. dass `cron.job` den Lock überhaupt anfordert).

### A4: Smoketests laufen lokal, in CI und über das Standard-Test-Skript

Die Tests werden in einer normalen `*.test.ts` ausgeführt, nicht in einem separaten Integration-Profil. Sie brauchen nur `sh` und ein temporäres Verzeichnis, also stehen sie überall, wo Vitest läuft. Sollten sie sich als zu flaky in einer bestimmten CI-Umgebung erweisen, kann eine spätere Iteration sie unter `vitest.distribution.config.ts` oder `vitest.integration.config.ts` ziehen — das ist keine Voraussetzung für den ersten Wurf.

### A5: Keine Live-Verifikation gegen `awk`

Die Smoketests führen das vollständige Shell-Statement aus; sie rufen `awk` aber nur indirekt über das Statement auf. Damit muss eine CI-Umgebung weiterhin nur `sh` haben (nicht `gawk`/`mawk`). Falls `awk` nicht installiert ist, sind nur die awk-spezifischen Tests betroffen — sie sollen das Fehlen sauber via `skipIf` melden, nicht crashen.

## Betroffene Dateien

| Datei                                                        | Beschreibung                                                                                                                       |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/flagLock.ts`                   | Holder-Readback von `ssh.output` auf `ssh.exec` umstellen, strukturierte Fehlermeldungen mit Exit-Code und Stderr ergänzen.        |
| `packages/paratix/test/modules/flagLock.shell.smoke.test.ts` | **Neu.** Smoketests, die die generierten Shell-Statements gegen ein echtes `/bin/sh` ausführen.                                    |
| `packages/paratix/test/modules/moduleHelpers.test.ts`        | Bestehende Tests gegen die neue Fehlermeldungsform anpassen (Substrings, kein voller String-Vergleich).                            |
| `packages/paratix/test/helpers/mockSshCommandResponses.ts`   | Ggf. Mock-Default-Antwort für den Holder-Readback erweitern, falls `kind` von `output` auf `exec` wechselt und neue Stubs braucht. |
| `packages/paratix/test/helpers/mockSshFlagLock.ts`           | Falls der Readback nun über `exec` läuft, das passende Internal-Default ergänzen, damit bestehende Tests grün bleiben.             |

## Implementierungsdetails

### Vorgehen

1. **Diagnose-Refactor in `flagLock.ts`.**
   1. Den `ssh.output("awk …").catch(() => "")`-Aufruf ersetzen durch `ssh.exec("awk …", { ignoreExitCode: true, silent: true })`.
   2. Auswerten: `code === 0 && token.length > 0` → Success-Pfad wie heute.
   3. Sonst: Lock-Verzeichnis aufräumen wie heute, dann strukturierte Failure liefern:
      - bei `code !== 0` → `failedCommand("[moduleHelpers] flag lock holder marker for <lockName> readback failed", result)`.
      - bei `code === 0 && trimmedToken.length === 0` → `failed("[moduleHelpers] flag lock holder marker for <lockName> is readable but empty")`.
   4. R-0000634-Kommentarblock aktualisieren, sodass die Begründung für `exec` statt `output` dokumentiert ist.

2. **Tests anpassen.**
   1. Bestehende `moduleHelpers.test.ts`-Erwartungen, die exakt auf die alte Fehlermeldung matchen, auf Substring-Asserts umstellen (`toContain("readback failed")` etc.).
   2. Mock-Helper anpassen, falls die neue `exec`-Anfrage einen separaten Stub braucht. Wahrscheinlich genügt es, das bestehende `isFlagLockHolderReadback`-Pattern auch für `exec` zu spiegeln.

3. **Smoketest-Datei anlegen.**
   1. Hilfsfunktion `runShell(commandLine, env?): { code, stdout, stderr }`, die `spawnSync('sh', ['-c', commandLine], { ...env })` kapselt.
   2. Pro Pfad ein Setup-Teardown mit `mkdtemp`/`rm -rf`.
   3. Drei Test-Cases (Happy-Path für `writeFlagLockHolderMarker`, `releaseFlagLock`, `tryReclaimStaleFlagLock`), die jeweils die exakten Strings aus dem Production-Code in `/bin/sh` ausführen und auf das beobachtete Ergebnis prüfen.
   4. `it.skipIf(!awkAvailable)` für die awk-abhängigen Cases.
4. **Validierung.** `pnpm agent:check` projektweit.

### Komponenten-Struktur

Nicht relevant — keine UI.

### State-Management

Nicht relevant.

### API-Anbindung

Nicht relevant — kein externer Aufruf.

### Styling-Ansatz

Nicht relevant.

### Barrierefreiheit

Nicht relevant.

### Edge Cases

- **awk fehlt im System.** Die Smoketests, die awk anfassen, werden via `skipIf` übersprungen. Auf Standard-Linux-CIs ist awk immer da; auf einer minimalen Container-CI kann es fehlen.
- **`sh` ist nicht verfügbar.** Auf typischen Vitest-Umgebungen unter Windows kann `sh` fehlen. Die Smoketest-Datei wird komplett übersprungen (`describe.skipIf(process.platform === "win32")`), damit Windows-Entwicklung nicht durch Plattform-Fremdsprache blockiert wird.
- **Temp-Verzeichnis enthält Spaces oder Unicode.** `mkdtemp(tmpdir() + "/paratix-shell-")` liefert auf jedem System einen schmerzfreien Pfad. Die Tests verwenden den exakten Pfad, sodass Quoting-Bugs entdeckt werden.
- **Marker-Datei ist tatsächlich leer.** Soll als eigene Klasse von Fehler erkannt werden („readable but empty"), abgrenzbar vom Readback-Fehler („readback failed: …").
- **Stderr enthält registrierte Secrets.** `failedCommand` läuft durch die existierende Maskierung; keine Eigenlösung.

## Akzeptanzkriterien

- [ ] Wenn `awk` mit einem nicht-Null-Exit beim Readback antwortet, enthält die Fehlermeldung von `acquireFlagLock` Exit-Code und Stderr. Manuell verifizierbar durch ein temporäres `awk … --`-Patchen im Production-Code (vor dem Refactor wäre die Meldung „is empty after write", nach dem Refactor wäre sie „readback failed: … EUSAGE …").
- [ ] Wenn die Marker-Datei real leer ist (z. B. via `: > marker`), bleibt die Fehlermeldung „readable but empty" (klar abgrenzbar vom Readback-Fehler).
- [ ] Die neue Smoketest-Datei läuft im normalen `pnpm test` mit, ist grün auf Linux/macOS, wird auf Windows übersprungen.
- [ ] `pnpm agent:check` projektweit grün — alle bestehenden Tests bleiben grün, kein Test-Refactor außerhalb der oben genannten Files.
- [ ] Issue 35 ist nicht wieder herstellbar, ohne dass mindestens ein Smoketest scheitert: das wird durch einen verifizierenden Spike vor dem Commit gezeigt (lokal `awk … --` ins Production-Skript zurückbiegen, Smoketests laufen lassen, erwarten dass sie rot werden).

## Validierungsplan

- **Unit-Tests:** angepasste `moduleHelpers.test.ts` deckt den neuen Failure-Pfad ab.
- **Smoketests:** neue `flagLock.shell.smoke.test.ts` validiert das echte Shell-Verhalten der drei kritischen Statements.
- **Manueller Spike:** im Implementierungs-Workflow kurz `awk … --` zurückbiegen und prüfen, dass mindestens ein Smoketest rot wird. Anschließend zurück auf die korrekte Form.
- **Pre-Commit-Gate:** `pnpm agent:check` projektweit.
- **Distribution-Test:** der existierende `pnpm test:dist`-Lauf darf nicht regredieren, weil Smoketests teil der `*.test.ts`-Pattern sind und sich auch in die distribution-Variante ziehen.

## Annahmen und offene Punkte

- **Annahme**: `sh` ist auf jeder Linux-/macOS-CI verfügbar. Stimmt für GitHub-Actions-`ubuntu-latest` und `macos-latest` (beide haben dash/bash).
- **Annahme**: `awk` ist auf den CI-Runnern verfügbar. Verifiziert über die existierenden Workflow-Runs.
- **Offen**: Falls ein User später auf Windows arbeiten will, müssen die Smoketests dort übersprungen werden — der `skipIf`-Mechanismus deckt das ab. Eine WSL-fokussierte Strategie ist nicht Teil dieses Plans.
- **Offen**: Sollten weitere Module mit eigenen Shell-Statements (z. B. `cron`, `net.hosts`, `sshd`) ähnliche Smoketests bekommen? Bewusst aus dem Scope: dieser Plan etabliert das Muster für den `flagLock`-Layer. Eine Folgeentscheidung kann das Muster ausweiten.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       0 |       1 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       0 |

### Befunde

- **Hinweis · Architektur:** Der Plan etabliert das Smoketest-Muster lokal im `flagLock`-Bereich. Falls das Muster sich bewährt, sollte es bewusst auf andere Shell-lastige Module (cron, net.hosts, sshd) ausgeweitet werden. Aktuell als „offen" in `Annahmen` dokumentiert; vor einer breiten Ausweitung sollte ein Folgeplan die Skalierungsfrage klären (sh-only vs. echte SSH-Integration).
- **Hinweis · Testbarkeit:** Die akzeptierte „awk-zurückbiegen"-Verifikation ist ein manueller Schritt im Implementierungs-Workflow. Wer den Refactor umsetzt, sollte das Ergebnis kurz dokumentieren (Wisdom oder Plan-Update), damit der Beweis nicht verloren geht.
- **Hinweis · Scope:** Plan A3/A4 schließt eine vollständige Mock-Ablösung explizit aus. Falls beim Refactoring auffällt, dass die Mock-Patterns aktuell wirklich keinen Mehrwert mehr leisten, sollte das als eigenes Refactor-Plan (0093+) gestartet werden, nicht im laufenden Lauf.

## Umsetzungsergebnis

### Geänderte Dateien

| Datei                                                                                     | Änderung                                                                                                                                                                                                                                                                           |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/flagLock.ts`                                                | `ssh.output` → `ssh.exec` für den Holder-Readback. Drei differenzierte Failure-Branches via `buildReadbackFailure` (extrahiert, weil sonst max-statements gerissen wird). `ExecResult` aus `../types.js` importiert.                                                               |
| `packages/paratix/test/modules/flagLock.shell.smoke.test.ts`                              | **Neu.** Sechs Smoketests gegen `/bin/sh` (3 × write/release/reclaim + Regression-Guard für issue #35 + 2 Sad-Path-Cases). `describe.skipIf(SKIP_PLATFORM \|\| SKIP_NO_AWK)`.                                                                                                      |
| `packages/paratix/test/modules/moduleHelpers.test.ts`                                     | Drei Mocks (`createSharedFlagMockSsh`, `createSharedMutexMockSsh`, `createStaleLockSsh`) im exec-Pfad um den Holder-Readback ergänzt. Empty-Readback-Test auf „is readable but empty" angepasst. Neuer `handleFlagLockInternalCommand`-Helper, um die Complexity-Grenze zu halten. |
| `packages/paratix/test/modules/cron.test.ts`                                              | `isFlagLockHolderReadback`-Import + exec-Handler für den Readback im Shared-Crontab-Mock.                                                                                                                                                                                          |
| `packages/paratix/test/modules/sshd/05-sshd-config-apply-validation-and-rollback.test.ts` | Holder-Readback im scripted exec sequence harness.                                                                                                                                                                                                                                 |
| `packages/paratix/test/modules/sshd/06-sshd-port-apply-validation-and-rollback.test.ts`   | dito + `mockExecResolvedValue` mit Readback-Pfad.                                                                                                                                                                                                                                  |
| `packages/paratix/test/modules/sshd/10-sshd-port-ufw-guard.test.ts`                       | Holder-Readback in den beiden bulk-exec-Spies (`spyExecSuccessAcceptingSsProbe`, `spyExecForUfwRaceAfterConfigWrite`).                                                                                                                                                             |

### Verhaltens-Invarianz

Erfolgs-Pfad bit-identisch zum Stand vor dem Refactor: gleicher Holder-Token, gleiche Release-Sequence, gleiche Cleanup-Reihenfolge bei Failures. Die einzigen sichtbaren Änderungen sind die Fehler-Texte beim fehlgeschlagenen Readback (jetzt drei differenzierte Varianten statt einer mehrdeutigen). Maskierung läuft weiterhin über `failedCommand` → `maskRegisteredSecrets`.

### Akzeptanzkriterien

- [x] Awk-non-zero-Exit surfacet Exit-Code + Stderr (`failedCommand`-Pfad).
- [x] Real-leerer Marker liefert `is readable but empty`.
- [x] Smoketest läuft im normalen `pnpm test`, grün auf macOS, Skip-Logik für Windows / fehlendes awk verifiziert.
- [x] `pnpm agent:check` projektweit grün.
- [x] Awk-Spike-Verifikation: mit `awk … --` zurückgepatcht werden 6 moduleHelpers-Tests rot (Mocks erkennen die `--`-Form nicht mehr). Smoketests bleiben unabhängig grün, weil sie das Shell-Verhalten direkt testen. Spike anschließend zurückgenommen.

### Testergebnisse

- Baseline: paratix unit 3860 / 99 Files, distribution 9, create-paratix 256+6, Workspace-Skripte 34.
- Nachher: paratix unit **3866** / 100 Files (+6 Smoketests, +1 File), restliche Zahlen identisch zur Baseline.
- Keine Regressionen, keine bestehenden Tests verändert über die in der Datei-Tabelle gelisteten hinaus.
