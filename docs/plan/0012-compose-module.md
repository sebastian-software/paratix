# 0012 — compose-Modul

## Anforderung

Implementierung des `compose`-Moduls zur Verwaltung von Docker Compose / Podman Compose Stacks auf entfernten Servern. Zusätzlich: Generierung von systemd-Service-Dateien zum automatischen Starten/Stoppen von Compose-Stacks beim Booten.

## Architekturentscheidungen

- **Runtime-Erkennung:** Automatische Erkennung über `command -v docker` / `command -v podman` mit optionalem explizitem Override via `runtime`-Parameter.
- **Parameter-Naming:** `projectDirectory` statt `projectDir` wegen `unicorn/prevent-abbreviations` Linter-Regel.
- **Options-Objekt-Pattern:** Alle Methoden verwenden ein Options-Objekt statt positioneller Parameter, da sie 2-4 Parameter haben.
- **systemd-Unit-Pfad:** `/usr/bin/env` statt hartkodiertem `/usr/bin/<runtime>` für portablere Pfadauflösung.
- **config Dual-API:** Akzeptiert sowohl `src` (lokale Datei) als auch `content` (String). Bei Angabe von beiden hat `src` Vorrang (konsistent in check und apply).

## Methoden

| Methode           | Typ            | Beschreibung                             |
| ----------------- | -------------- | ---------------------------------------- |
| `compose.up`      | Idempotent     | Stellt sicher, dass alle Services laufen |
| `compose.pull`    | Signal-ähnlich | Zieht neueste Images                     |
| `compose.down`    | Idempotent     | Stoppt/entfernt Container                |
| `compose.config`  | Idempotent     | Deployt compose.yml + validiert          |
| `compose.restart` | Signal         | `down && up -d`                          |
| `compose.systemd` | Idempotent     | Generiert systemd-Service-Unit           |

## Betroffene Dateien

| Datei                                           | Aktion                  |
| ----------------------------------------------- | ----------------------- |
| `packages/paratix/src/modules/compose.ts`       | Neu erstellt            |
| `packages/paratix/src/modules/index.ts`         | Export hinzugefügt      |
| `packages/paratix/test/modules/compose.test.ts` | Neu erstellt (72 Tests) |

## Review-Findings und deren Behebung

1. **Inkonsistente src/content-Priorität** in `compose.config` zwischen check und apply → Behoben: `src` hat jetzt überall Vorrang.
2. **Hartkodierter `/usr/bin/` Pfad** in systemd-Unit → Behoben: Verwendet `/usr/bin/env`.
3. **Fehlende Newline-Validierung** in `generateSystemdUnit` → Behoben: `sanitizeUnitValue` Helper strippt `\n`/`\r`.
4. **compose.up check ignorierte services-Filter** → Behoben: `ps`-Befehl enthält jetzt Service-Filter.

## Testergebnisse

- 72 Unit-Tests, alle bestanden
- Gesamtprojekt: 488 Tests bestanden, 0 Fehler
- TypeScript: 0 Fehler
- Linting: 0 Fehler
- Formatierung: OK
