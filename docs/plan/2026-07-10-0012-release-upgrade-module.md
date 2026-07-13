# 0012 — releaseUpgrade module

## Anforderung

Neues `releaseUpgrade`-Modul für OS-Versions-Upgrades (z.B. Ubuntu 22.04 → 24.04, Debian Bullseye → Bookworm). Unterstützt Ubuntu und Debian. Automatischer Reboot und Reconnect nach dem Upgrade. Dry-Run-Option zur Simulation.

## Architekturentscheidungen

### Eigenständiges Modul

Das Modul lebt in `releaseUpgrade.ts` — nicht Teil von `apt` (das nur Paket-Operationen macht) oder `system` (das nur Reboot/Uptime bietet). Ein Release-Upgrade ist eine eigenständige, komplexe Operation.

### Distro-Erkennung

Die Distribution wird automatisch aus `/etc/os-release` erkannt (`ID=ubuntu` oder `ID=debian`). Unbekannte Distributionen führen zu `{ status: "failed" }`.

### Ubuntu-Pfad

- **Check:** `do-release-upgrade -c` — exit 0 bedeutet Upgrade verfügbar
- **Apply:** `apt-get update` + `do-release-upgrade -f DistUpgradeViewNonInteractive`
- **Dry-Run:** Führt nur `do-release-upgrade -c` aus

### Debian-Pfad

- **Check:** Vergleicht aktuellen Codename (`lsb_release -cs`) mit dem Debian-Stable-Codename (abgefragt via HTTPS von `deb.debian.org/debian/dists/stable/Release`)
- **Apply:** Ersetzt Codename in `/etc/apt/sources.list` und allen `.list`/`.sources`-Dateien in `/etc/apt/sources.list.d/`, dann `apt-get update` + `apt-get full-upgrade` + `apt-get autoremove`
- **Dry-Run:** Keine Änderungen, gibt `{ status: "ok" }` zurück

### Reboot und Reconnect

Folgt dem bestehenden Meta-Signal-Pattern aus `system.reboot`:

- `meta: { "system.reboot": "true" }` wird gesetzt
- Optional: `resolveHost()` liefert neue IP → `meta: { "system.host": "new-ip" }`
- Runner erkennt `system.reboot` und ruft `reconnect()` auf

### Idempotenz

Kein Flag-File nötig. Die Check-Phase prüft direkt ob ein Upgrade verfügbar ist:

- Ubuntu: `do-release-upgrade -c` ist die autoritative Quelle
- Debian: Codename-Vergleich

### Security

- Codenames werden nach dem Einlesen via Regex validiert (`/^[a-z]{3,20}$/`) um Injection über manipulierte `lsb_release`-Ausgabe oder HTTP-Responses zu verhindern
- Debian Release-Metadaten werden über HTTPS abgefragt
- DEB822-Format (`.sources`-Dateien) wird neben `.list`-Dateien berücksichtigt

### Error Handling

- Die Check-Phase für den Debian-Pfad ist in try/catch gewrappt, sodass Fehler bei der Codename-Ermittlung den Runner nicht abbrechen (gibt `NEEDS_APPLY` zurück)
- `resolveHost`-Fehler werden still ignoriert (Fallback auf aktuellen Host)

## Workflow-Position

Wird typischerweise am Anfang eines Playbooks eingesetzt (nach SSH-Härtung), damit alle nachfolgenden Module auf dem aktuellen OS laufen.

## Betroffene Dateien

| Datei                                                  | Änderung                  |
| ------------------------------------------------------ | ------------------------- |
| `packages/paratix/src/modules/releaseUpgrade.ts`       | NEU: releaseUpgrade-Modul |
| `packages/paratix/src/modules/index.ts`                | Export hinzugefügt        |
| `packages/paratix/test/modules/releaseUpgrade.test.ts` | NEU: 19 Unit-Tests        |

## Testergebnisse

19 Tests abdeckend:

- Check-Phase: 6 Tests (Ubuntu upgrade/no-upgrade, Debian codename-match/mismatch, unknown distro, no SSH)
- Apply Ubuntu: 4 Tests (happy path, dryRun, update-fail, upgrade-fail)
- Apply Debian: 4 Tests (happy path, dryRun, update-fail, full-upgrade-fail, autoremove-fail)
- Apply General: 4 Tests (no SSH, unknown distro, resolveHost success, resolveHost failure)

## Review-Findings und Behebung

| Finding                                 | Schweregrad | Behebung                                    |
| --------------------------------------- | ----------- | ------------------------------------------- |
| Codename-Validierung fehlte             | Kritisch    | Regex-Validierung für Codenames hinzugefügt |
| HTTP statt HTTPS für Debian Release     | Wichtig     | URL auf HTTPS geändert                      |
| `.sources`-Dateien nicht berücksichtigt | Wichtig     | find-Befehl um `.sources` erweitert         |
| Exception in check-Phase                | Wichtig     | try/catch für Debian-Pfad in check          |
| Fehlender autoremove-Test               | Hinweis     | Test hinzugefügt                            |
