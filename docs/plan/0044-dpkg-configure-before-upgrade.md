# 0044: dpkg --configure -a vor apt-get full-upgrade

## Anforderung

Debian-Upgrade in `releaseUpgrade.ts` war nicht robust bei wiederholter Ausfuehrung nach Abbruechen. Halb-konfigurierte Pakete aus vorherigen abgebrochenen Laeufen konnten das Upgrade zum Scheitern bringen. Loesung: Vor `apt-get full-upgrade` ein `dpkg --configure -a` ausfuehren.

## Architekturentscheidungen

- **Platzierung nach `apt-get update` und vor `apt-get full-upgrade`** — dpkg muss nach dem Update der Paketlisten laufen, aber bevor neue Pakete installiert werden, damit halb-konfigurierte Pakete zuerst repariert werden.
- **`DEBIAN_FRONTEND=noninteractive`** — noetig weil `dpkg --configure -a` bei halb-konfigurierten Paketen interaktive Conffile-Prompts ausloesen kann, die in einer SSH-Session haengen wuerden.
- **Sofortiger Abbruch bei Fehler** (`status: "failed"`) — wenn dpkg --configure -a fehlschlaegt, ist das Paketsystem inkonsistent. Ein full-upgrade wuerde mit hoher Wahrscheinlichkeit ebenfalls fehlschlagen.

## Betroffene Dateien

| Datei                                                  | Beschreibung                                                 |
| ------------------------------------------------------ | ------------------------------------------------------------ |
| `packages/paratix/src/modules/releaseUpgrade.ts`       | `dpkg --configure -a` Schritt eingefuegt, JSDoc aktualisiert |
| `packages/paratix/test/modules/releaseUpgrade.test.ts` | 2 neue Tests, debianApplyResponses erweitert                 |

## Implementierungsdetails

### Upgrade-Sequenz (4 Schritte)

1. `apt-get update` — Paketlisten aktualisieren
2. `dpkg --configure -a` — halb-konfigurierte Pakete reparieren (NEU)
3. `apt-get full-upgrade -y` — Upgrade durchfuehren
4. `apt-get autoremove -y` — nicht mehr benoetigte Pakete entfernen

### Tests

- "Debian: returns failed when dpkg --configure -a fails" — Fehlerfall-Test
- "Debian: runs dpkg --configure -a after apt-get update and before apt-get full-upgrade" — Reihenfolge-Test

### Validierung

- Lint (oxlint + eslint): 0 Fehler
- Prettier: bestanden
- TypeScript: 0 Fehler
- Tests: 1241 bestanden (41 Test-Dateien)

## Review-Findings

Keine Findings. Review bestanden ohne Beanstandungen.
