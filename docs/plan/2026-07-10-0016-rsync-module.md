# 0016 — rsync Module

## Anforderung

Implementierung des `rsync.sync` Moduls zur Datei-Synchronisation vom Controller auf den Server via rsync ueber SSH.

## Architekturentscheidungen

- **Kein lokales Modul**: Das Modul erhaelt die `SshConnection`, liest Verbindungsdaten via `getConnectionInfo()`, und fuehrt `rsync` lokal via `child_process.execFile` aus.
- **execFile statt exec**: Vermeidet Shell-Interpretation und schuetzt vor Command Injection.
- **`--` Separator**: Trennt rsync-Flags von Positional-Argumenten (src/dest) als Schutz gegen Argument Injection.
- **privateKeyPath in Anfuehrungszeichen**: Der SSH-Key-Pfad wird im `-e` Transport-String gequotet, um Pfade mit Leerzeichen zu unterstuetzen.
- **Idempotenz**: `check()` nutzt `--dry-run --itemize-changes` — leerer Output bedeutet "ok". `apply()` gibt `changed` oder `ok` basierend auf dem tatsaechlichen rsync-Output zurueck.
- **Error Logging**: Fehler werden via `console.error` geloggt statt verschluckt, um Debugging zu ermoeglichen.

## Betroffene Dateien

| Aktion    | Datei                                         |
| --------- | --------------------------------------------- |
| Erstellt  | `packages/paratix/src/modules/rsync.ts`       |
| Geaendert | `packages/paratix/src/modules/index.ts`       |
| Erstellt  | `packages/paratix/test/modules/rsync.test.ts` |

## Implementierungsdetails

### rsync.ts

- Einzige Methode: `rsync.sync(options: SyncOptions): Module`
- Parameter: `src`, `dest`, `exclude`, `include`, `delete`, `owner`, `group`, `chmod`
- Drei Hilfsfunktionen: `buildFilterArguments()`, `buildOwnershipArguments()`, `buildArguments()`
- SSH-Transport: `ssh -p PORT -i "KEY" -o StrictHostKeyChecking=no`
- `--chown=owner:group` mit Fallback (nur owner → owner:owner, nur group → :group)

### index.ts

- Export `{ rsync }` alphabetisch zwischen `releaseUpgrade` und `service` eingefuegt.

## Testergebnisse

- 24 Unit-Tests in `rsync.test.ts`
- Testbereiche: check, apply, name, argument building
- child_process.execFile wird via `vi.mock` gemockt
- 608 Tests gesamt bestehen

## Review-Findings und Behebung

1. **Argument Injection** → `--` Separator vor src/dest eingefuegt
2. **privateKeyPath mit Leerzeichen** → Pfad in Anfuehrungszeichen im SSH-Transport
3. **Falscher Status** → `apply()` gibt nun `ok` zurueck wenn nichts geaendert wurde
4. **Verschluckte Fehler** → `console.error` in beiden catch-Bloecken
