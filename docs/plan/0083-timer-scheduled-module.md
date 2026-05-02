# 0083 — Timer Scheduled Module

## Anforderung

Helper-Modul `timer.scheduled(name, options)` als systemd-Timer-Pendant zu `cron.job`. Eine einzige Modul-Zeile soll `<name>.service` (`Type=oneshot`) und `<name>.timer` schreiben, `daemon-reload` ausführen und den Timer aktivieren und starten — symmetrisch zu `cron.job`, aber mit den Vorteilen von systemd-Timern (`Persistent=` für nachgeholte Läufe, journald-Logging, reichere Schedule-Sprache).

## API

```typescript
timer.scheduled(name: string, options: {
  exec: string                         // ExecStart=
  onCalendar: string | string[]        // OnCalendar=
  description?: string                 // [Unit] Description, default: "Paratix scheduled task: <name>"
  user?: string                        // [Service] User=
  group?: string                       // [Service] Group=
  workingDirectory?: string            // [Service] WorkingDirectory=
  environment?: Record<string, string> // [Service] Environment=KEY=VAL
  persistent?: boolean                 // [Timer] Persistent=true (default: true)
  randomizedDelaySec?: number | string // [Timer] RandomizedDelaySec=
  accuracySec?: number | string        // [Timer] AccuracySec=
  state?: "absent" | "present"         // default: "present"
}): Module
```

`name = "backup"` ⇒ `/etc/systemd/system/backup.service` und `/etc/systemd/system/backup.timer`.

## Architekturentscheidungen

### Eigenes Top-Level-Modul `timer`

Symmetrisch zu `cron`, klares User-Mental-Modell „statt cron nimm timer". Methode `scheduled` heißt explizit so, weil sie nicht bloß einen einzelnen `.timer` schreibt, sondern beide Units koordiniert.

### All-in-one-Apply

Apply orchestriert intern alle Schritte: `writeFile × 2` → `daemon-reload` → `systemctl enable --now <name>.timer` → optional `systemctl restart <name>.timer`. Konsistent mit dem Multi-Step-Pattern aus `quadlet.container`. Der User soll nicht zusätzlich `service.enabled`/`service.running` aufrufen müssen.

### Idempotenz auf Sub-Schritt-Ebene

`apply` führt `writeFile`, `daemon-reload` und `restart` nur dann aus, wenn der jeweilige Sub-State nicht stimmt:

- `writeFile` pro Datei nur, wenn der Inhalt abweicht
- `daemon-reload` nur, wenn mindestens eine Datei geändert wurde
- `restart` nur, wenn der `.timer`-Inhalt sich geändert hat (sonst hätte `enable --now` bereits gestartet, und ein `restart` würde nur einen laufenden oneshot-Job abbrechen)

`enable --now` bleibt unbedingt — es ist idempotent und stellt sicher, dass der Timer aktiviert und aktiv ist.

### Defaults

- `Persistent=true` (Hauptvorteil ggü. cron — verpasste Läufe werden nachgeholt)
- `Type=oneshot` für die generierte `.service`
- `WantedBy=timers.target` als Install-Target
- `[Install]` fehlt im `.service` bewusst (nur Timer-getriggert)

### Validierung

Alle Validierung läuft nur bei `state: "present"`, damit ein Aufrufer beim Entfernen eines Timers keine Dummy-Werte für `exec`/`onCalendar` liefern muss:

- `name` matcht `/^[A-Za-z0-9_\-]+$/v` — keine Punkte/Endungen, kein `@` (Template-Units bewusst nicht supportet), keine Unicode-Word-Chars
- `exec` darf weder Newlines enthalten noch leer sein
- `description`, `user`, `group`, `workingDirectory` und Environment-Werte werden auf Newlines geprüft (Newlines würden die Unit-Datei korrumpieren)
- Environment-Keys matchen `/^[A-Za-z_][A-Za-z0-9_]*$/v`
- `onCalendar` darf nicht leer sein, einzelne Einträge dürfen weder leer sein noch Newlines enthalten

### Environment-Quoting

Werte mit Whitespace, `"` oder `\` werden gequotet (`Environment=KEY="value with space"`). Eingebettete `"` und `\` werden escaped. Werte ohne diese Zeichen bleiben unquoted, um lesbare Unit-Dateien zu produzieren.

### `state: "absent"`

`disable --now` (Best-Effort, ignoriert Fehler bei nicht existenten Units) → `rm -f` beider Unit-Dateien → `daemon-reload`. `disable --now` entfernt auch den `wants/`-Symlink, daher reicht ein `daemon-reload` am Ende.

`check` mit `state: "absent"` ist „ok", sobald beide Unit-Dateien fehlen.

## Betroffene Dateien

| Datei                                         | Aktion   |
| --------------------------------------------- | -------- |
| `packages/paratix/src/modules/timer.ts`       | Neu      |
| `packages/paratix/test/modules/timer.test.ts` | Neu      |
| `packages/paratix/src/modules/index.ts`       | Geändert |
| `packages/paratix/llm-guide.md`               | Geändert |
| `cspell.json`                                 | Geändert |
| `docs/plan/0083-timer-scheduled-module.md`    | Neu      |

## Implementierungsdetails

- Modul-Pattern wie `cron.ts`/`quadlet.ts`: closure-basierter Zustand (`paths` bzw. `locations`), idempotente `check`/`apply`-Funktionen
- `fileMatches(ssh, path, expected)` als gemeinsamer Helper für `check` und `apply`
- `syncUnitFiles` extrahiert Datei-Schreiben + `daemon-reload` aus `applyPresent`, um die `max-statements`-Regel einzuhalten
- Alle dynamischen Werte in `systemctl`-Aufrufen via `shellQuote()`
- ASCII-only Name-Pattern, um Surprise mit Unicode-Hostnamen oder Path-Edgecases zu vermeiden

## Testergebnisse

44 Tests in `timer.test.ts`, alle bestanden:

- **check (present)**: 7 Tests — ok bei vollständigem Match, needs-apply für jeden möglichen Drift (fehlende Files, Content-Drift, nicht enabled, nicht active, null SSH)
- **check (absent)**: 3 Tests — ok bei fehlenden Files, needs-apply pro residualem File
- **apply (present)**: 5 Tests — Erfolg + Failures pro Sub-Step + null SSH
- **apply (state: present, idempotency)**: 2 Tests — kein restart bei Match, kein restart wenn nur `.service` geändert
- **apply (absent)**: 4 Tests — Erfolg, Disable-Ignore, rm-Fail, reload-Fail
- **unit content**: 4 Tests — Multiple OnCalendar, Hardening-Felder, `Persistent=false`, RandomizedDelaySec/AccuracySec
- **environment quoting**: 3 Tests — Whitespace, embedded quotes/backslashes, simple values bleiben unquoted
- **module name and validation**: 16 Tests — Name-Regeln (Punkt, Pfad, Metachar, Non-ASCII), exec-Regeln, onCalendar-Regeln, description/user/group/workingDirectory Newline-Checks, environment Key-Pattern und Value-Newline, absent skipt Validierung

## Review-Findings und Behebung

Internes nodejs-reviewer-Review hat 14 Findings geliefert. Behoben:

| Finding                                                                        | Bereich     | Behebung                                                                                                                         |
| ------------------------------------------------------------------------------ | ----------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Restart läuft auch ohne Content-Change                                         | Idempotenz  | `restart` nur, wenn `.timer`-Datei tatsächlich geändert wurde                                                                    |
| `description`, `user`, `group`, `workingDirectory`, env-key fehlen Validierung | Sicherheit  | `assertNoNewline` für alle textuellen Felder; `ENVIRONMENT_KEY_PATTERN` für env-Keys                                             |
| Environment-Werte mit Whitespace zerbrechen Parsing                            | Korrektheit | `quoteEnvironmentValue` quotet Werte mit Whitespace/`"`/`\`                                                                      |
| API zwingt zu Dummy-Werten bei `state: "absent"`                               | API         | Validierung wird übersprungen; Render-Funktionen werden bei absent gar nicht aufgerufen (separate `TimerLocations` ohne Content) |
| Name-Pattern erlaubt Unicode-Word-Chars                                        | Validierung | ASCII-only Pattern, Test deckt `bäckup` ab                                                                                       |

Bewusst nicht umgesetzt (mit Begründung):

- `wants/`-Symlink-Cleanup im `applyAbsent`: `systemctl disable --now` entfernt den Symlink selbst, zusätzliche Checks wären over-engineering
- Fehlendes `[Install]` im `.service`: bewusstes Design, nur Timer-getriggert
- `mkdir -p '/etc/systemd/system'` vor `writeFile`: konsistent mit `systemd.unit` weglassen
- `try/catch` um `writeFile` mit explizitem `failedCommand`: konsistent mit `systemd.unit`/`quadlet`

## Validierung

- `pnpm lint` — clean (oxlint + eslint)
- `pnpm format:check` — clean
- `pnpm typecheck` — clean
- `pnpm test` — 1704 von 1705 Tests grün; der eine Failure (CLI Versionsstring `0.7.0-68e7b5a` vs. erwartet `0.8.0`) ist ein vorbestehender Build-Versionierungs-Test, nicht durch dieses Feature verursacht
