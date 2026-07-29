# 0051: Belastbarer Dry-Run für SSH-Hardening

## Anforderung

`sshd.config` und `sshd.port` sollen im Dry-Run nicht mehr nur pauschal als `changed` erscheinen. Paratix soll die prospective `sshd_config` belastbarer prüfen und zugleich klar ausweisen, welche Runtime-Risiken im Dry-Run bewusst nicht verifiziert werden.

## Architekturentscheidungen

- `sshd.config` und `sshd.port` erhalten einen dedizierten `_applyDryRun`-Pfad.
- Der Dry-Run schreibt eine temporäre prospective Konfiguration auf den Zielhost und prüft sie mit `sshd -t -f <tempfile>`.
- Reload, Restart, Portwechsel, Firewall-Erreichbarkeit und Reconnect bleiben im Dry-Run bewusst deaktiviert.
- Für solche verifizierten, aber bewusst unvollständigen Dry-Runs nutzt Paratix einen internen `_dryRunDetail`-Kanal im `ModuleResult`, damit Runner und Recipe-Dry-Run die Grenzen explizit ausgeben können.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                   |
| -------------------------------------------- | ------------------------------------------------------------------------------ |
| `packages/paratix/src/modules/sshd.ts`       | Eigene Dry-Run-Verifikation für `sshd.config` und `sshd.port`                  |
| `packages/paratix/src/types.ts`              | Interner `_dryRunDetail`-Kanal im `ModuleResult`                               |
| `packages/paratix/src/runner.ts`             | Dry-Run-Ausgabe für Module mit custom Dry-Run-Detail                           |
| `packages/paratix/src/dryRunRecipe.ts`       | Gleiche Dry-Run-Ausgabe für Recipe-Kinder                                      |
| `packages/paratix/src/cli.ts`                | Präzisierter `--dry-run`-Hilfetext                                             |
| `packages/paratix/README.md`                 | Dokumentation der verifizierten und nicht verifizierten SSH-Hardening-Dry-Runs |
| `packages/paratix/test/modules/sshd.test.ts` | Regressionen für `sshd -t`-Verifikation und fehlende Runtime-Seiteneffekte     |
| `packages/paratix/test/runner.test.ts`       | Regressionen für Dry-Run-Ausgabe und fehlende Reconnect-Seiteneffekte          |

## Implementierungsdetails

- `sshd.config._applyDryRun()` und `sshd.port._applyDryRun()` bauen dieselbe prospective Konfiguration wie der echte Apply-Pfad.
- Die prospective Konfiguration wird via Tempdatei mit `sshd -t -f` geprüft und danach wieder entfernt.
- Bei Validerungserfolg liefert `sshd.config` den Detailhinweis `reload not executed`.
- Bei Validerungserfolg liefert `sshd.port` den Detailhinweis, dass `restart`, `port switch`, `firewall` und `reconnect` nicht verifiziert wurden.
- Bei `sshd -t`-Fehlern liefert der Dry-Run ein echtes `failed` mit diagnostischem `error`.
- Der Runner druckt im Dry-Run für solche Module nicht mehr nur `(dry-run)`, sondern den jeweiligen Detailhinweis.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/modules/sshd.test.ts test/runner.test.ts`
- `pnpm --filter paratix exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen Findings nach finaler Eigenprüfung.
