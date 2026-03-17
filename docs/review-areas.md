# Review-Bereiche

1. Security (kritisch), unter anderem:
   - SSH-Verbindungsmanagement (ssh.ts, sshHelpers.ts) – Private-Key-Handling, Sudo-Passwort-Caching, Reconnect-Logik
   - Remote Command Execution (command.ts) – Shell-Injection-Risiken, Secrets-Masking
   - Download-Modul (download.ts) – Header-Injection, Checksum-Verifizierung, URL-Escaping
   - SFTP/File-Operationen (sftp.ts, file.ts) – Temp-File-Handling, atomare Schreibvorgänge, Berechtigungen
   - Template-System (template.ts) – Injection über Platzhalter-Werte
   - Environment/Secrets (environment.ts) – .env-Parsing, Secret-Leaking in Logs/Fehlermeldungen
   - TOTP-Implementierung (totp.ts) – Korrektheit der RFC 6238/4226 Umsetzung
2. Robustheit & Fehlerbehandlung, unter anderem:
   - Idempotenz-Garantien – Verhalten der Module bei Netzwerk-Abbrüchen, Timeouts, halben Zuständen
   - Reconnect-Logik – Exponential Backoff, Verhalten bei SSH-Port-Änderungen
   - Graceful Shutdown – SIGINT/SIGTERM-Handling, offene SFTP-Transfers
   - Error Recovery – Was passiert bei Fehlern mitten in einer Playbook-Ausführung?
3. Testabdeckung & -qualität, unter anderem:
   - Mocking vs. Integration – Tests nutzen gemockte SSH-Verbindungen; gibt es auch E2E-Tests gegen echte Server?
   - Edge Cases – Leere Eingaben, Unicode, sehr große Dateien, Race Conditions
   - Modul-Testabdeckung – Alle 17+ Module ausreichend getestet?
4. Code-Qualität & Architektur, unter anderem:
   - TypeScript Strict Mode – Nutzung von any, Type Assertions, ungeprüfte Casts
   - Dependency Review – ssh2 als kritische Dependency (Aktualität, bekannte CVEs)
   - Konsistenz der Module (einheitliches Error-Handling, Logging, Rückgabewerte)
   - Runner-Logik (runner.ts, runnerHelpers.ts) – Orchestrierung, Signal-System
5. Ops & DX, unter anderem:
   - CLI-Validierung (cli.ts) – Fehlermeldungen, Input-Sanitierung
   - Dry-Run-Modus – Vollständigkeit und Zuverlässigkeit
   - Logging & Observability – Ausreichend für Debugging im Produktiveinsatz?
   - create-paratix Scaffolding – Erzeugt es sichere Defaults?
