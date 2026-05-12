# 0088: create-paratix Dist-CLI-Erfolgspfad

## Anforderung

Der Postbuild-Distributionstest von `create-paratix` soll nicht nur frühe Usage-Fehler prüfen, sondern auch eine erfolgreiche Scaffold-Ausführung über `dist/index.js` abdecken. Der Test muss den publizierten CLI-Einstieg, `main()`, Argument-Parsing, nicht-interaktive Host- und Admin-Key-Auflösung, Projektanlage und Installer-Aufruf validieren.

## Architekturentscheidungen

- **Postbuild-E2E statt Unit-Test**: Die Abdeckung liegt in `packages/create-paratix/test/postbuild/cli.dist.test.ts`, weil nur dort das gebaute `dist/index.js` getestet wird.
- **Temporärer Package-Manager-Stub**: Der Test setzt `npm_config_user_agent` auf pnpm und stellt über einen temporären `PATH` einen ausführbaren `pnpm`-Stub bereit. Dadurch läuft der echte Installer-Pfad, ohne Netzwerk oder echte Dependency-Installation auszuführen.
- **Vollständig nicht-interaktiver CLI-Aufruf**: Der Test übergibt Projektname, `--host`, `--initial-user`, `--expected-host-fingerprint` und `--admin-public-key`, damit keine TTY-Prompts beteiligt sind.
- **Realpath-normalisierte Temp-Pfade**: Der Test normalisiert den temporären CWD mit `realpathSync`, damit macOS-Pfade unter `/var` und `/private/var` konsistent verglichen werden.

## Betroffene Dateien

| Datei                                                     | Beschreibung                                                                   |
| --------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `packages/create-paratix/test/postbuild/cli.dist.test.ts` | Ergänzt den Dist-CLI-Erfolgspfad inklusive Installer-Stub und Datei-Assertions |
| `docs/plan/0088-create-paratix-dist-cli-success-path.md`  | Dokumentiert Anforderung, Entscheidungen, Validierung und Review-Ergebnis      |

## Implementierungsdetails

Der neue Postbuild-Test erzeugt ein temporäres Arbeitsverzeichnis mit separatem `bin`-Verzeichnis. Dort schreibt er einen ausführbaren `pnpm`-Stub, der den aufgerufenen CWD und die Argumente in eine Logdatei schreibt. Anschließend startet der Test `dist/index.js` mit `process.execPath` und vollständigen nicht-interaktiven Flags.

Die Assertions prüfen Exit-Code `0`, leeres `stderr`, Erfolgs- und Installationsausgabe, den Installer-Aufruf mit `pnpm install`, erzeugte Scaffold-Dateien sowie zentrale Inhalte in `package.json` und `server.ts`.

## Testergebnisse

- `pnpm --filter create-paratix test:dist` – bestanden, 3 Tests

## Review-Findings

Kein separater Reviewer gestartet, weil die Änderung ausschließlich fokussierte Testabdeckung für den bereits bestehenden CLI-Erfolgspfad ergänzt und durch den betroffenen Postbuild-Test validiert wird.
