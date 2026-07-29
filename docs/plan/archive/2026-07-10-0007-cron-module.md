# 0007 — Cron Module

## Anforderung

Neues Modul `cron.job` zur deklarativen Verwaltung von Crontab-Eintraegen ueber SSH. Ermoeglicht das idempotente Hinzufuegen, Aktualisieren und Entfernen von Cron-Jobs in der Crontab eines Benutzers.

## API

```typescript
cron.job(user: string, name: string, options: { job: string; state?: "absent" | "present" }): Module
```

- **user** — Linux-Benutzer, dessen Crontab verwaltet wird
- **name** — Eindeutiger Bezeichner (wird als Kommentar-Marker `# paratix: <name>` verwendet)
- **options.job** — Vollstaendige Crontab-Zeile inkl. Schedule und Command
- **options.state** — `"present"` (default) oder `"absent"`

## Architekturentscheidungen

### Marker-basierte Identifikation

Jobs werden ueber einen Kommentar-Marker `# paratix: <name>` identifiziert, der direkt vor der Cron-Zeile steht. Das ermoeglicht:

- Eindeutige Zuordnung auch bei identischen Schedules
- Update in-place bei Job-Aenderungen
- Sauberes Entfernen ohne Seiteneffekte auf andere Eintraege

### API-Signatur mit Options-Objekt

Statt `cron.job(user, name, job, options?)` wurde `cron.job(user, name, { job, state? })` gewaehlt, um die ESLint `max-params`-Regel (max 3 Parameter) einzuhalten. Das ist konsistent mit `file.block`.

### Hilfsfunktionen

Drei interne Hilfsfunktionen extrahiert:

- `readCrontab(ssh, user)` — Liest Crontab, gibt leeres Array bei Exit-Code 1 (keine Crontab)
- `writeCrontab(ssh, user, lines)` — Schreibt Crontab oder entfernt sie bei leerem Array via `crontab -r`
- `hasMarkedJob(lines, marker, cronJob)` — Prueft ob Marker + korrekte Job-Zeile existiert

### Input-Validierung

`name` und `job` werden auf Newlines (`\n`, `\r`) geprueft und werfen einen Error, da Zeilenumbrueche die Marker-Logik brechen wuerden.

## Betroffene Dateien

| Datei                                        | Aktion    |
| -------------------------------------------- | --------- |
| `packages/paratix/src/modules/cron.ts`       | Neu       |
| `packages/paratix/test/modules/cron.test.ts` | Neu       |
| `packages/paratix/src/modules/index.ts`      | Geaendert |
| `cspell.json`                                | Geaendert |

## Testergebnisse

21 Tests in `cron.test.ts`, alle bestanden:

- **check (present)**: 5 Tests — ok/needs-apply fuer vorhandene/fehlende/unterschiedliche Jobs, leere Crontab, null SSH
- **check (absent)**: 3 Tests — ok/needs-apply fuer fehlende/vorhandene Marker, leere Crontab
- **apply (present)**: 4 Tests — Anhaengen, Ersetzen, leere Crontab, null SSH
- **apply (absent)**: 4 Tests — Entfernen, nichts zu entfernen, letzer Job (crontab -r), null SSH
- **name**: 1 Test — korrektes Format
- **edge cases**: 2 Tests — Marker als letzte Zeile, mehrere Marker in einer Crontab
- **input validation**: 2 Tests — Newline in name/job wirft Error

## Review-Findings und Behebung

1. **Newline-Validierung** — Input-Validierung fuer `name` und `job` hinzugefuegt (Review-Finding)
2. **Edge-Case-Tests** — Tests fuer Marker als letzte Zeile und mehrere Marker ergaenzt (Review-Finding)
3. **apply() gibt immer "changed"** — Konsistent mit bestehenden Modulen (ssh.ts), bewusst nicht geaendert
