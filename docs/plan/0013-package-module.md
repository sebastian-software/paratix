# 0013 — Package Module

## Anforderung

Distro-agnostisches Paketmanagement-Modul, das automatisch den verfügbaren Paketmanager erkennt (apt, dnf, yum, apk) und ein einheitliches Interface für Paketoperationen bereitstellt.

## Architekturentscheidungen

- **PM-Erkennung:** `detectPackageManager()` prüft via `which <binary>` in der Reihenfolge apt → dnf → yum → apk. Wird bei jedem `check`/`apply` neu aufgerufen (kein Cache), analog zu anderen Modulen die ihren Zustand bei jedem Aufruf frisch lesen.
- **Naming:** `package` ist ein JavaScript Reserved Word. Interner Export heißt `pkg`, re-exportiert als `package` via `export { pkg as package }` in `index.ts`.
- **Idempotenz:** `installed`/`absent` prüfen einzelne Pakete über PM-spezifische Befehle. `update`/`upgrade` verwenden datierte Flag-Dateien in `/var/lib/paratix/flags/` (gleiches Pattern wie `apt.distUpgrade`).
- **apt-Refactoring:** `apt.installed`, `apt.absent`, `apt.upgrade` wurden entfernt, da durch `package` ersetzt. `apt` behält nur Debian-spezifische Methoden: `debconf`, `distUpgrade`, `key`, `repository`.
- **Robustere Paketprüfung (apt):** Statt `dpkg -l | grep` wird `dpkg-query -W -f='${Status}'` verwendet, um False Positives durch Beschreibungsspalten-Matches zu vermeiden.
- **Input-Validierung:** `installed()` und `absent()` werfen bei leerer Paketliste einen Fehler (analog zu `cron.job` bei Newlines im Namen).

## Betroffene Dateien

| Datei                                           | Aktion                                                                    |
| ----------------------------------------------- | ------------------------------------------------------------------------- |
| `packages/paratix/src/modules/package.ts`       | Neu erstellt                                                              |
| `packages/paratix/src/modules/index.ts`         | Export hinzugefügt                                                        |
| `packages/paratix/src/modules/apt.ts`           | `installed`, `absent`, `upgrade` entfernt                                 |
| `packages/paratix/test/modules/package.test.ts` | Neu erstellt (41 Tests)                                                   |
| `packages/paratix/test/modules/apt.test.ts`     | Tests für entfernte Methoden entfernt                                     |
| `README.md`                                     | Modul-Tabelle, Beispiel-Playbook und "not implemented"-Liste aktualisiert |

## API

```typescript
import { package as pkg } from "paratix/modules"

// Pakete installieren (erkennt PM automatisch)
pkg.installed("nginx", "curl", "git")

// Pakete entfernen
pkg.absent("apache2")

// Paketlisten aktualisieren (einmalig pro Datum)
pkg.update("2026-03-13")

// System-Upgrade (einmalig pro Datum)
pkg.upgrade("2026-03-13")
```

## Befehlsmapping

| Aktion  | apt                                    | dnf              | yum              | apk                         |
| ------- | -------------------------------------- | ---------------- | ---------------- | --------------------------- |
| install | `apt-get install -y`                   | `dnf install -y` | `yum install -y` | `apk add`                   |
| remove  | `apt-get remove -y`                    | `dnf remove -y`  | `yum remove -y`  | `apk del`                   |
| update  | `apt-get update`                       | `dnf makecache`  | `yum makecache`  | `apk update`                |
| upgrade | `apt-get update && apt-get upgrade -y` | `dnf upgrade -y` | `yum update -y`  | `apk update && apk upgrade` |
| check   | `dpkg-query -W -f='${Status}'`         | `rpm -q`         | `rpm -q`         | `apk info -e`               |

## Testergebnisse

- 41 neue Tests (39 Modul-Tests + 2 Input-Validierung)
- 522 Tests gesamt, alle bestanden
- Lint: 0 Errors
- TypeScript: 0 Errors
- Formatting: bestanden

## Review-Findings und Behebung

| #   | Severity | Issue                                   | Behebung                                     |
| --- | -------- | --------------------------------------- | -------------------------------------------- |
| F2  | WICHTIG  | `dpkg -l \| grep` fragil                | Ersetzt durch `dpkg-query -W -f='${Status}'` |
| F4  | WICHTIG  | Keine Validierung für leere Paketlisten | `throw new Error()` hinzugefügt              |
| F5  | MINOR    | `name` bei `installed` inkonsistent     | Geändert zu `package.installed:`             |
