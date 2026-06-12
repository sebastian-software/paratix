# 0090: Dry-Run-Diff-Ausgabe

**Planungsstatus:** Umgesetzt
**Empfohlener Workflow:** /build

## Anforderung

Paratix soll im Dry-Run-Modus optional einen Diff anzeigen, der pro Modul deutlich macht, _was_ sich konkret ändern würde – nicht nur _dass_ sich etwas ändert. Aktivierung über ein neues CLI-Flag `--diff`, das nur in Verbindung mit `--dry-run` greift.

Die Ausgabe orientiert sich am bekannten Unified-Diff-Format (z. B. „Terraform plan"-Stil), mit roten `-` und grünen `+` Zeilen unter der jeweiligen Modulzeile.

Beispiel:

```
  ↺  /etc/ssh/sshd_config                            changed  (dry-run)
     │ --- current
     │ +++ desired
     │ -Port 22
     │ +Port 2222
     │ -PasswordAuthentication yes
     │ +PasswordAuthentication no
```

### Hintergrund

- Die heutige Dry-Run-Ausgabe meldet pro Modul lediglich `changed (dry-run)` bzw. `ok`.
- `check()` liefert nur `"ok" | "needs-apply"` – die Drift wird nicht strukturiert erfasst.
- `_dryRunDetail?: string` (`types.ts:64`) existiert, ist aber `@internal`, nur einzeiliger Suffix und für nur drei Module genutzt.
- Es gibt heute kein CLI-Flag, das Drift-Inhalte sichtbar macht.

### Nicht-Ziele

- Diff-Ausgabe im echten Apply (ohne `--dry-run`). Bewusst Out-of-Scope für diesen Plan.
- Strukturierter JSON-Export oder Machine-Readable-Output.
- Diff für jedes Modul. Erstausstattung: `file.content`, `file.template`, `sysctl`, `swap`, `cron`/`timer`, `hostname`, `net.hosts`, sowie als Bonus `quadlet.container` (gemeinsamer File-Diff-Helper).
- Änderung der `check()`-Signatur. Diffs werden über das bestehende `_applyDryRun`-Pattern produziert, nicht über eine erweiterte `check()`-Methode.

## Architekturentscheidungen

### A1: Öffentliches `diff?: string` auf `ModuleResult`

`ModuleResult` bekommt ein neues optionales Feld `diff?: string` (ohne Unterstrich, damit es Teil der öffentlichen Modul-API ist und Drittautoren es nutzen können).

- Mehrzeiliger String im Unified-Diff-Format. Keine Strukturierung, keine ANSI-Codes – das Rendering passiert im Output-Layer.
- Optional. Module ohne Diff-Support liefern wie bisher nur `status: "changed"`.

### A2: `RunOptions.diff?: boolean` + CLI-Flag `--diff`

- Neue Option `--diff` im `apply`-Command.
- Validierung im CLI: `--diff` ohne `--dry-run` ist ein Eingabefehler. Vor dem Run wird abgebrochen mit klarer Meldung (Exit-Code 2, kein Stack-Trace).
- `RunOptions.diff: boolean` wird durch den Runner an die Dry-Run-Pfade propagiert.

### A3: `_dryRunDiffProducer`-Marker auf Modulen

Analog zu `_dryRunBlocker` und `_dryRunMetaProducer` markiert ein Modul mit `_dryRunDiffProducer: true`, dass es im Dry-Run einen Diff über `_applyDryRun` liefern kann.

- Der Dry-Run-Pfad (`runner.ts`/`dryRunRecipe.ts`) ruft `_applyDryRun` **nur dann zusätzlich auf**, wenn `runOptions.diff === true` und das Modul den Marker trägt und `check()` `"needs-apply"` ergab.
- Ohne Flag, ohne Marker oder bei `check() === "ok"`: kein zusätzlicher Roundtrip, kein Diff.
- Module ohne `_applyDryRun` zeigen weiterhin nur `changed (dry-run)`.

### A4: Diff-Helper als reine Utility

Neuer `packages/paratix/src/modules/diffHelpers.ts` mit:

- `buildUnifiedDiff(current: string, desired: string, options?: { contextLines?: number; currentLabel?: string; desiredLabel?: string }): string`
- intern: einfacher zeilenbasierter LCS- oder Patience-Diff. **Keine** externe Lib (Bundle-Größe, Audit-Surface). Implementierung kompakt (~80 Zeilen).
- Ergebnis: Plaintext-Unified-Diff inkl. `---/+++/@@`-Header.
- Spezialfall: leerer `current` → "new file"-Marker; leerer `desired` → "deleted"-Marker.

### A5: Output-Rendering mit ANSI-Farbcode

In `output.ts`:

- Neuer Renderpfad in `printRenderedModuleResult` über einen optionalen `diff?: string`-Parameter (oder neue dedizierte Hilfsfunktion `printModuleDiff`).
- Pro Diff-Zeile:
  - `---` / `+++` / `@@` → dimm
  - `-` Zeilen → rot
  - `+` Zeilen → grün
  - Kontextzeilen → dim
- Continuation-Indentation analog zu `detailLines`, mit vertikalem Guide `│ ` als Präfix.
- Alle Diff-Zeilen laufen vor Ausgabe durch `maskRegisteredSecrets` und `sanitizeTerminalText` – wichtig, weil File-Inhalte registrierte Tokens enthalten können.
- Live-Spinner-Pfad (`activeSpinner != null`): wie heute, die Diff-Zeilen folgen nach dem Linewrap der Statuszeile.

### A6: Inkrementelle Modul-Bestückung

Phase 2 implementiert Diffs für folgende Module. Jedes Modul ist isoliert testbar; Reihenfolge so gewählt, dass der File-Diff-Helper früh existiert und von späteren Modulen wiederverwendet wird.

| Reihenfolge | Modul                            | Diff-Inhalt                                                                                                                 |
| ----------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| 1           | `file.content` / `file.template` | Unified Diff zwischen Remote-Datei und Soll-Inhalt; bei nicht existierender Datei: alle `+` Zeilen mit Hinweis `(new file)` |
| 2           | `sysctl`                         | Pro relevantem Key eine `key = value`-Drift im Unified-Format                                                               |
| 3           | `swap`                           | Konfigurations-Drift (Größe, swappiness, vfs_cache_pressure)                                                                |
| 4           | `cron` / `timer`                 | Drift der Crontab- bzw. Timer-Unit-Datei                                                                                    |
| 5           | `hostname` + `net.hosts`         | Hostname alt → neu, `/etc/hosts` als Unified Diff                                                                           |
| 6 (Bonus)   | `quadlet.container`              | gleicher File-Diff-Helper, wenn Restzeit reicht                                                                             |

Falls einzelne Module komplex werden, dürfen sie in einen separaten Folgeplan gehen. Das Feature ist auch dann ausgeliefert: jede Aktivierung in einem Modul ist additiv und ändert die öffentliche API nicht erneut.

### A7: Geheimnis-Maskierung als verpflichtender Schritt

Diffs müssen sämtliche Maskierungen passieren:

1. `maskRegisteredSecrets` (registrierte op/Token-Werte)
2. `sanitizeTerminalText` (Terminal-Escape-Sicherheit)
3. die Maskierung erfolgt **im Output-Layer**, nicht im Diff-Helper. Module liefern den rohen Diff; das Rendering verantwortet die Sicherheit. Damit gilt R-0000789 (Defense-in-Depth) implizit auch hier.

## Betroffene Dateien

| Datei                                                                                                              | Beschreibung                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/paratix/src/types.ts`                                                                                    | `ModuleResult.diff?: string` ergänzen; `_dryRunDiffProducer?: true` im Module-Typ ergänzen                                                 |
| `packages/paratix/src/runner.ts`                                                                                   | `RunOptions.diff?: boolean`; Dry-Run-Pfad ruft `_applyDryRun` zusätzlich, wenn Flag + Marker gesetzt; Diff an Output-Layer übergeben       |
| `packages/paratix/src/dryRunRecipe.ts`                                                                             | analog für Sub-Recipes: Flag durchreichen, Diff an Output übergeben                                                                        |
| `packages/paratix/src/cli.ts`                                                                                      | `--diff` Option im `apply`-Command; Validierung `--diff` ohne `--dry-run` lehnt ab; `ApplyCommandOptions.diff`                             |
| `packages/paratix/src/output.ts`                                                                                   | Diff-Rendering (`printModuleDiff` oder Erweiterung von `printRenderedModuleResult`); Farben über `picocolors`; Maskierung & Sanitizer-Pfad |
| `packages/paratix/src/modules/diffHelpers.ts`                                                                      | **neu**: `buildUnifiedDiff` + Hilfsfunktionen                                                                                              |
| `packages/paratix/src/modules/file.ts`                                                                             | `_dryRunDiffProducer: true`, `_applyDryRun` für `file.content`/`file.template`                                                             |
| `packages/paratix/src/modules/fileExtra.ts`                                                                        | ggf. analoge Anpassungen für `fileExtra.content`-Pfade                                                                                     |
| `packages/paratix/src/modules/sysctl.ts`                                                                           | Diff über die einzelnen Keys                                                                                                               |
| `packages/paratix/src/modules/swap.ts`                                                                             | Konfigurations-Drift-Diff                                                                                                                  |
| `packages/paratix/src/modules/cron.ts` + `cronMutation.ts`                                                         | Crontab-Diff                                                                                                                               |
| `packages/paratix/src/modules/timer.ts`                                                                            | Timer-Unit-Diff                                                                                                                            |
| `packages/paratix/src/modules/hostname.ts`                                                                         | Hostname-Drift                                                                                                                             |
| `packages/paratix/src/modules/net.ts`                                                                              | `/etc/hosts`-Diff                                                                                                                          |
| `packages/paratix/src/modules/quadlet.ts` + `quadletFileHelpers.ts`                                                | Quadlet-File-Diff (Bonus, gemeinsamer Helper)                                                                                              |
| `packages/paratix/test/modules/diffHelpers.test.ts`                                                                | **neu**: Tests für `buildUnifiedDiff`                                                                                                      |
| `packages/paratix/test/modules/file.test.ts`, `sysctl.test.ts`, `swap.test.ts`, `cron.test.ts`, `hostname.test.ts` | Erweiterung um Diff-Assertions                                                                                                             |
| `packages/paratix/test/runner-dry-run.test.ts`                                                                     | Test: `runOptions.diff === true` ruft `_applyDryRun` zusätzlich, sonst nicht                                                               |
| `packages/paratix/test/cli.test.ts`                                                                                | `--diff` Parsing + Validierung gegen `--dry-run`                                                                                           |
| `packages/paratix/test/output.test.ts`                                                                             | Diff-Rendering inkl. Farben/Maskierung/Sanitizer                                                                                           |
| `packages/paratix/llm-guide.md`                                                                                    | Doku-Update für Modulautoren: wie liefert ein Modul einen Diff?                                                                            |
| `packages/paratix/README.md`                                                                                       | `--diff`-Flag in der CLI-Sektion                                                                                                           |
| `README.md` (Root)                                                                                                 | nur erwähnen, falls Root-README das `apply`-Flag-Set zeigt                                                                                 |

## Akzeptanzkriterien

1. `pnpm paratix apply server.ts --dry-run --diff` zeigt für mindestens die Module `file.content`, `file.template`, `sysctl`, `swap`, `cron`, `hostname` einen mehrzeiligen Unified-Diff in Farbe.
2. `pnpm paratix apply server.ts --diff` (ohne `--dry-run`) bricht mit klarer Fehlermeldung ab und Exit-Code 2. Es wird kein SSH-Connect aufgebaut.
3. `pnpm paratix apply server.ts --dry-run` (ohne `--diff`) verhält sich exakt wie heute. Keine zusätzlichen Remote-Roundtrips. Keine Diff-Ausgabe.
4. `pnpm paratix apply server.ts` (ohne beide Flags) verhält sich exakt wie heute.
5. Module ohne Diff-Support zeigen weiterhin nur `changed (dry-run)`, auch mit `--diff`.
6. Registrierte Secrets erscheinen in keinem Diff. Verifiziert durch einen Output-Test, der ein Secret in einem geänderten File platziert und auf maskierte Ausgabe prüft.
7. `ModuleResult.diff` ist als öffentliches optionales Feld im exportierten Typ sichtbar (typ-getestet im `publicApi.test.ts`).
8. `pnpm agent:check` läuft sauber durch.

## Validierungsplan

1. **Unit-Tests**
   - `diffHelpers.test.ts`: leere Eingabe, ein Zeilen-Unterschied, mehrere Hunks, new-file, deleted-file.
   - `output.test.ts`: Diff-Rendering mit ANSI-Codes (oder bei mock-tty ohne), Continuation-Indent, Secret-Maskierung, Terminal-Sanitizing.
   - Modul-Tests pro implementiertem Modul: assert auf `result.diff`-Substrings (z. B. `-Port 22`, `+Port 2222`).
2. **Integrations-Tests**
   - `runner-dry-run.test.ts`: `runOptions.diff === false` ruft kein `_applyDryRun` auf, `runOptions.diff === true` ruft es auf und Diff fließt in Output.
   - `cli.test.ts`: `--diff` mit `--dry-run` parsed; `--diff` ohne `--dry-run` → Fehlerpfad.
3. **Pre-Commit-Gate**: `pnpm agent:check` (Type-Check, Lint, Tests).
4. **Manueller Smoke-Test**: dieser Plan dokumentiert kein Live-Run gegen einen echten Server, weil Dry-Run lokal verifizierbar ist.

## Implementierungsdetails

### Reihenfolge der Phase-2-Schritte

1. `types.ts` + `cli.ts` + `runner.ts` + `dryRunRecipe.ts`: Verkabelung des Flags ohne Diff-Inhalt.
2. `output.ts`: Renderer + Tests.
3. `diffHelpers.ts`: Implementierung + Tests.
4. `file.ts`: erste Modul-Integration mit `_dryRunDiffProducer` + `_applyDryRun`. Ende-zu-Ende verifizierbar.
5. Schrittweise weitere Module: sysctl → swap → cron/timer → hostname/net.hosts → quadlet (Bonus).

### `_applyDryRun`-Pfad pro Modul

Ein Modul mit Diff-Support implementiert zusätzlich:

```ts
async _applyDryRun(connection, env): Promise<ModuleResult> {
  // ohne Mutation: aktuellen Remote-Inhalt lesen und mit Soll vergleichen
  const current = await readRemote(...)
  const desired = renderDesired(...)
  if (current === desired) return { status: "ok" }
  return {
    status: "changed",
    diff: buildUnifiedDiff(current, desired, { currentLabel: pathOrKey, desiredLabel: "desired" }),
  }
}
```

und setzt am Module-Objekt `_dryRunDiffProducer: true`.

Der Runner ruft `_applyDryRun` im Dry-Run nur dann auf, wenn `runOptions.diff === true` **und** `check()` `"needs-apply"` ergab. Sonst bleibt der bisherige Pfad bestehen.

### Output-Beispiel (vollständig)

```
[s1]
  [base-setup]
  · ↺  /etc/sysctl.d/99-paratix.conf                  changed  (dry-run)
  ·    │ --- /etc/sysctl.d/99-paratix.conf
  ·    │ +++ desired
  ·    │ -vm.swappiness = 60
  ·    │ +vm.swappiness = 10
  · ↺  /etc/ssh/sshd_config                           changed  (dry-run)
  ·    │ -Port 22
  ·    │ +Port 2222
```

### Backwards-Compatibility

- `ModuleResult.diff` ist optional → existierende Module unverändert.
- `_dryRunDiffProducer` ist optional → existierende Module unverändert.
- Ohne `--diff` ist das Laufzeitverhalten bit-identisch zum Status quo (keine zusätzlichen Calls, kein verändertes Output).
- Öffentliche API-Erweiterung dokumentiert in `llm-guide.md`.

## Offene Fragen

- **Quadlet als Pflicht oder Bonus?** Aktuell als Bonus gelistet. Falls die ersten fünf Module gut laufen und Restzeit bleibt, ziehen wir Quadlet noch rein. Sonst Folgeplan.
- **Diff-Kontextzeilen-Default?** Im Helper Default `contextLines: 3`, ohne CLI-Override. Für sehr kurze Dateien wird automatisch der gesamte Inhalt gezeigt.

## Umsetzungsergebnis

### Tatsächlich umgesetzte Module

| Modul                                       | Status                        |
| ------------------------------------------- | ----------------------------- |
| `file.copy`                                 | Umgesetzt                     |
| `file.template`                             | Umgesetzt                     |
| `sysctl.set`                                | Umgesetzt                     |
| `swap.swappiness` / `swap.vfsCachePressure` | Umgesetzt (über `sysctl.set`) |
| `hostname.set`                              | Umgesetzt                     |
| `cron` / `timer`                            | Nicht umgesetzt (Folgeplan)   |
| `swap.file`                                 | Nicht umgesetzt (Folgeplan)   |
| `net.hosts`                                 | Nicht umgesetzt (Folgeplan)   |
| `quadlet.container` (Bonus)                 | Nicht umgesetzt (Folgeplan)   |

Diff-Erzeugung für `cron`/`timer`, `swap.file`, `net.hosts` und `quadlet.container` wurde zugunsten eines klaren ersten Wurfs verschoben. Die öffentliche API (`ModuleResult.diff`, `_dryRunDiffProducer`, `--diff` Flag) ist bereits in der jetzigen Form stabil, sodass die übrigen Module rein additiv ergänzt werden können.

### Architekturanpassung gegenüber Plan

- Die Logik `shouldExecuteApplyDuringDryRun` wurde nach `packages/paratix/src/dryRunDispatch.ts` extrahiert (statt sie wie ursprünglich angedacht in beiden Aufrufern zu wiederholen). Damit teilen sich `runner.ts` und `dryRunRecipe.ts` denselben Marker-Dispatch.

### Testergebnisse

- `pnpm agent:check` läuft fehlerfrei durch (Lint, Format, Typecheck, Build, Tests).
- Test-Summary:
  - `paratix` unit: **3831 passed**
  - `paratix` distribution: **9 passed**
  - `create-paratix` unit: **256 passed**
  - `create-paratix` distribution: **6 passed**
  - Workspace-Skript-Tests: **34 passed**
- Neue/erweiterte Test-Dateien:
  - `packages/paratix/test/modules/diffHelpers.test.ts` (neu)
  - `packages/paratix/test/runner-dry-run.test.ts` (3 neue Cases)
  - `packages/paratix/test/cli.test.ts` (`--diff` Validierung)
  - `packages/paratix/test/output.test.ts` (Diff-Rendering inkl. Secret-Maskierung)
  - `packages/paratix/test/modules/{file,sysctl,hostname}.test.ts` (Diff-Produktion pro Modul)

## Review-Findings

**Datum:** 2026-06-12
**Reviewer:** orchestrator-internes Review (Phase 6)

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      1 |
| Offen / Nicht umgesetzt |      4 |

**Externer Review-Report:** `.sf-plugin/review/review-report-2026-06-12-plan-0090.md`
