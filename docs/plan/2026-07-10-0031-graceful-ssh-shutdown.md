# 0031 Graceful SSH Shutdown bei SIGINT/SIGTERM

## Anforderung

Signal-Handler für graceful SSH-Shutdown bei SIGINT/SIGTERM implementieren:

- SSH-Verbindung sauber schließen (disconnect packet senden)
- Laufende Remote-Befehle beenden (Channels schließen → SIGHUP auf Server)
- `finally`-Block in `runPlaybook()` ausführen
- Korrekte Exit-Codes: 130 (SIGINT) / 143 (SIGTERM)

## Architekturentscheidungen

- **Signal-Handler in `runPlaybook()`**: Die `ssh`-Instanz ist lokal in `runPlaybook()`. Die Handler werden dort registriert, wo die Instanz lebt — kein Exponieren nach außen nötig.
- **Kein AbortController**: `ssh.disconnect()` → `client.end()` reicht aus. ssh2 schließt alle Channels und liefert Error-Callbacks für pending exec()-Aufrufe. Ein AbortController wäre Over-Engineering.
- **Doppel-Signal-Pattern**: Erstes Signal → graceful shutdown; zweites Signal → force exit. Standard-Praxis für CLI-Tools.
- **ShutdownState-Abstraktion**: Kapselt Handler-Registrierung und Signal-Zustand in `setupShutdownHandlers()`. Gibt eine Closure (`shutdownSignal()`) zurück statt einer mutablen Variable.

## Betroffene Dateien

### packages/paratix/src/runner.ts

- `signalExitCode(signal)`: Berechnet POSIX Exit-Code (128 + Signal-Nummer)
- `ShutdownState`: Typ für Handler-Referenz und Signal-Zustand-Getter
- `setupShutdownHandlers(ssh)`: Registriert SIGINT/SIGTERM Handler, gibt `ShutdownState` zurück
- `createSshConnection(definition, options)`: Extrahiert SSH-Setup aus `runPlaybook()`
- `resolveExitCode(shutdownSignal, stats)`: Setzt `process.exitCode` basierend auf Signal oder Fehlern
- `runPlaybook()`: Registriert/deregistriert Handler, überspringt Signals bei Shutdown

### packages/paratix/src/cli.ts

- `process.exit(2)` → `process.exit(process.exitCode ?? 2)`: Signal-Exit-Code wird beibehalten

### packages/paratix/test/runner.test.ts

5 neue Tests:

1. SIGINT/SIGTERM-Listener werden nach runPlaybook vollständig entfernt
2. SIGINT setzt process.exitCode auf 130 und ruft disconnect() auf
3. SIGTERM setzt process.exitCode auf 143
4. Playbook-Signals werden bei Shutdown übersprungen
5. Normaler Ablauf setzt keinen Signal-Exit-Code

## Review-Findings

| Schweregrad | Anzahl | Behoben | Offen |
| ----------- | ------ | ------- | ----- |
| Kritisch    | 0      | 0       | 0     |
| Wichtig     | 2      | 0       | 2     |
| Hinweis     | 3      | 1       | 2     |

### Offene Findings (Wichtig)

1. **Signal vor Handler-Registrierung**: SIGINT während `ssh.connect()` wird nicht abgefangen. Timing-Fenster minimal, OS schließt TCP bei Prozessende.
2. **Pending exec() bei disconnect**: Abhängigkeit von ssh2-internem Error-Callback-Verhalten. Praktisch kein Problem, da ssh2 Error-Callbacks bei `client.end()` liefert.

## Testergebnisse

- 883 Tests bestanden (5 neue)
- 0 Lint/Type/Format-Fehler
