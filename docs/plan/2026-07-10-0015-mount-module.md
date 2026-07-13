# 0015 — mount Module

## Anforderung

Implementierung des Moduls `mount` fuer idempotentes Management von Filesystem-Mounts und `/etc/fstab`-Eintraegen auf Remote-Servern via SSH.

## Methoden

### `mount.present(options)`

Stellt sicher, dass ein Dateisystem gemountet ist. Erstellt den Mountpoint automatisch (`mkdir -p`). Persistiert optional in `/etc/fstab` (Standard: `true`).

**Parameter:**

- `path` — Mountpoint
- `src` — Device oder virtuelles Dateisystem (z.B. `"tmpfs"`, `"/dev/sdb1"`)
- `fstype` — Dateisystemtyp (z.B. `"ext4"`, `"tmpfs"`, `"nfs"`)
- `opts` — Mount-Optionen (z.B. `"noexec,nosuid,nodev,size=512m"`)
- `persist` — In `/etc/fstab` eintragen (Standard: `true`)

**Check-Strategie:** `findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS <path>` + fstab-Eintrag vergleichen

### `mount.absent(options)`

Stellt sicher, dass ein Mountpoint nicht gemountet ist. Entfernt optional den fstab-Eintrag.

**Parameter:**

- `path` — Mountpoint
- `persist` — fstab-Eintrag entfernen (Standard: `true`)

**Check-Strategie:** `findmnt --noheadings <path>` + fstab-Eintrag pruefen

## Architekturentscheidungen

- **fstab-Identifikation:** Eintraege werden ueber den Mountpoint (2. Feld) identifiziert
- **fstab-Format:** `<src> <path> <fstype> <opts> 0 0` (dump=0, pass=0)
- **Kein Remount:** Wenn bereits gemountet, wird nicht remountet — fstab wird aktualisiert, Mount greift beim naechsten Reboot. Grund: Remount bei laufendem System ist riskant.
- **changed/ok-Tracking:** `apply` gibt nur `"changed"` zurueck wenn tatsaechlich eine Aenderung stattfand (mount/umount/fstab-write), sonst `"ok"`
- **Trailing Newline:** fstab-Helpers stellen sicher, dass die Datei immer mit einer Newline endet (POSIX-konform)

## Betroffene Dateien

| Aktion    | Datei                                         |
| --------- | --------------------------------------------- |
| Erstellt  | `packages/paratix/src/modules/mount.ts`       |
| Geaendert | `packages/paratix/src/modules/index.ts`       |
| Erstellt  | `packages/paratix/test/modules/mount.test.ts` |
| Erstellt  | `docs/plan/0015-mount-module.md`              |

## Implementierungsdetails

### Private Helper-Funktionen

- `buildFstabLine(entry)` — Baut eine fstab-Zeile aus den Mount-Parametern
- `findFstabEntry(fstabContent, path)` — Findet einen fstab-Eintrag anhand des Mountpoints
- `upsertFstabEntry(fstabContent, path, newLine)` — Ersetzt oder haengt einen fstab-Eintrag an
- `removeFstabEntry(fstabContent, path)` — Entfernt einen fstab-Eintrag
- `ensureFstabEntry(ssh, path, desiredLine)` — Koordiniert Lesen/Vergleichen/Schreiben

### Test-Abdeckung

30 Tests:

- 7 Tests fuer `mount.present — check`
- 10 Tests fuer `mount.present — apply`
- 5 Tests fuer `mount.absent — check`
- 8 Tests fuer `mount.absent — apply`

### Review-Findings und Behebung

1. **Immer "changed"** — Behoben: `changed`-Flag trackt ob tatsaechlich Aenderungen stattfanden
2. **Trailing-Newline-Handling** — Behoben: `upsertFstabEntry` und `removeFstabEntry` stellen abschliessende Newline sicher, leere Trailing-Zeilen werden vor Append entfernt
3. **Kein Remount** — Bewusste Designentscheidung, dokumentiert in JSDoc

## Validierung

- Lint: 0 Errors
- Format: Bestanden
- Typecheck: Bestanden
- Tests: 590 bestanden (584 paratix + 6 create-paratix)
