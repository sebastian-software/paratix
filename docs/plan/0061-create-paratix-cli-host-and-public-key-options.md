# Plan 0061: create-paratix CLI host and public key options

## Anforderung

Host und Admin-Public-Key sollen in `create-paratix` nicht nur interaktiv, sondern auch vollständig
über CLI-Parameter gesetzt werden können.

## Architekturentscheidungen

- `--host` bleibt der kanonische CLI-Parameter für Domain/IP.
- Für den Admin-Key gibt es zwei explizite CLI-Pfade:
  - `--admin-public-key <value>`
  - `--admin-public-key-file <path>`
- Beide Flags sind gegenseitig exklusiv.
- CLI-Werte haben Vorrang vor dem interaktiven `~/.ssh`-Auswahlpfad.

## Betroffene Dateien

| Datei                                               | Beschreibung                             |
| --------------------------------------------------- | ---------------------------------------- |
| `packages/create-paratix/src/scaffoldConfig.ts`     | CLI-Parser um Public-Key-Flags erweitert |
| `packages/create-paratix/src/publicKeySelection.ts` | Public-Key-Validierung und File-Lesen    |
| `packages/create-paratix/src/index.ts`              | Priorität CLI vor interaktivem Prompt    |
| `packages/create-paratix/test/index.test.ts`        | Regressionen für neue CLI-Flags          |
| `packages/create-paratix/README.md`                 | Doku für nicht-interaktive Beispiele     |

## Implementierungsdetails

- Parser liefert jetzt `adminPublicKey` und `adminPublicKeyFile`.
- Direkte Key-Werte und Key-Dateien werden auf einzeilige SSH-Public-Keys validiert.
- `main()` löst den finalen Key in dieser Reihenfolge auf:
  1. `--admin-public-key`
  2. `--admin-public-key-file`
  3. interaktive Auswahl aus `~/.ssh`
  4. Placeholder im Template

## Testergebnisse

- Parser-Regressionsfälle für beide neuen Flags
- Konfliktfall beider Flags gleichzeitig
- Template-Injektion eines CLI-supplied Keys
