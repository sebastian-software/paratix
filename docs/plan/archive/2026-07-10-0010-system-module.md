# 0010 — system module

## Anforderung

Neues `system`-Modul mit zwei Methoden:

- `system.reboot(options?)` — Server neu starten mit automatischem Reconnect. Optionale `resolveHost`-Funktion ermöglicht dynamische IP-Auflösung nach Reboot (z.B. für Cloud-Instanzen mit wechselnder IP).
- `system.uptime()` — Aktuelle Server-Uptime auslesen und als Environment-Meta für nachfolgende Module bereitstellen.

## Architekturentscheidungen

### Meta-Signal-Pattern für Reconnect

Der Reconnect nach Reboot folgt dem bestehenden Pattern aus `handlePortChange`:

1. Modul sendet `shutdown -r now` und gibt `meta: { "system.reboot": "true" }` zurück
2. Optional: `resolveHost()` liefert neue IP → `meta: { "system.host": "new-ip" }`
3. Runner erkennt `system.reboot` in Meta und ruft `updateHost()` + `reconnect()` auf

### Host-Mutabilität

`SshConnectionImpl.host` wurde von `private readonly` zu `private` geändert. Neue `updateHost(host: string)` Methode auf Implementation und Interface.

### Error-Handling bei resolveHost

`resolveHost()` ist in try/catch gewrappt. Bei Fehler wird ohne `system.host` fortgefahren — der Reconnect versucht den bisherigen Host. Dies verhindert, dass ein DNS-Fehler den Reconnect nach bereits ausgelöstem Reboot blockiert.

## Betroffene Dateien

| Datei                                          | Änderung                                                    |
| ---------------------------------------------- | ----------------------------------------------------------- |
| `packages/paratix/src/modules/system.ts`       | NEU: system-Modul mit reboot() und uptime()                 |
| `packages/paratix/src/modules/index.ts`        | Export hinzugefügt                                          |
| `packages/paratix/src/ssh.ts`                  | host mutable, updateHost() Methode                          |
| `packages/paratix/src/types.ts`                | updateHost in SshConnection Interface                       |
| `packages/paratix/src/runner.ts`               | handleReboot() Funktion                                     |
| `packages/paratix/test/modules/system.test.ts` | NEU: 12 Unit-Tests                                          |
| `packages/paratix/test/helpers/mockSsh.ts`     | updateHost noop hinzugefügt                                 |
| `README.md`                                    | system in Modul-Tabelle, aus "not yet implemented" entfernt |

## Testergebnisse

12 Tests für system-Modul, 328 Tests gesamt — alle grün.

## Review-Findings und deren Behebung

1. **resolveHost Error Handling** — resolveHost() in try/catch gewrappt, damit Reconnect auch bei DNS-Fehlern stattfindet
2. **updateHost im Interface** — In SshConnection Interface aufgenommen, analog zu addPort
3. **Test für resolveHost-Fehler** — Neuer Test "falls back to current host when resolveHost throws" ergänzt
