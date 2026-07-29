# 0033 Error Message Truncation

## Anforderung

Error-Messages in `sshHelpers.ts` enthielten vollstaendige stdout/stderr mit Denylist-basierter Secret-Maskierung, aber ohne Laengenbegrenzung. Bei langen Ausgaben (z.B. `apt-get upgrade`) wurden Fehlermeldungen unlesbar.

**Ziel:** stdout/stderr auf max. 500 Zeichen pro Feld truncaten, Hinweis auf `--verbose` fuer Details geben, und `--verbose` funktional umsetzen.

## Architekturentscheidungen

### CommandError-Klasse

Neue `CommandError extends Error` in `sshHelpers.ts` mit:

- `fullStdout` / `fullStderr` Properties: enthalten den vollen, maskierten Output
- `.message`: enthaelt truncated Output + Hint-Text bei Truncation
- Masking erfolgt VOR Truncation (Security: keine partiell maskierten Secrets)

### Verbose-Threading

`--verbose` Flag wird von `cli.ts` ueber `RunOptions` durch alle Ebenen durchgefaedelt:

```
cli.ts (options.verbose)
  -> runPlaybook (RunOptions.verbose)
    -> runModuleLoop (LoopArguments.verbose)
      -> runRegularModule (RegularModuleArguments.verbose)
      -> runRecipeModule (verbose parameter)
    -> runSignals (SignalArguments.verbose)
```

### printCommandFailure

Neue zentrale Funktion in `output.ts`:

1. Ruft `printCommandError("", String(error))` auf (truncated Message)
2. Bei `verbose && error instanceof CommandError`: ruft `printVerboseCommandError()` auf (voller Output)

## Betroffene Dateien

| Datei                     | Aenderung                                                        |
| ------------------------- | ---------------------------------------------------------------- |
| `src/sshHelpers.ts`       | `CommandError` Klasse, `truncateOutput()`, `MAX_OUTPUT_LENGTH`   |
| `src/output.ts`           | `printVerboseCommandError()`, `printCommandFailure()`            |
| `src/runner.ts`           | `verbose` in `RunOptions` + Threading, `connectAndRegister`      |
| `src/cli.ts`              | `verbose` an `runPlaybook` durchgereicht                         |
| `test/sshHelpers.test.ts` | 13 neue Tests fuer Truncation, CommandError, Hint                |
| `test/output.test.ts`     | 17 neue Tests fuer printVerboseCommandError, printCommandFailure |

## Testergebnisse

- 943 Tests bestehen (30 neue)
- Lint: 0 Fehler, 0 Warnungen
- TypeScript: 0 Fehler
- Prettier: alle Dateien formatiert

## Review-Findings

| ID    | Titel                          | Schweregrad | Status                                           |
| ----- | ------------------------------ | ----------- | ------------------------------------------------ |
| R-001 | Unicode-sichere Truncation     | Hinweis     | Nicht umgesetzt (geringes Risiko bei SSH-Output) |
| R-002 | Error.captureStackTrace        | Hinweis     | Nicht umgesetzt (Stack wird nicht angezeigt)     |
| R-003 | Redundanter Output in verbose  | Hinweis     | Nicht umgesetzt (Design-Entscheidung)            |
| R-004 | Connect-Error Dokumentation    | Wichtig     | Nicht umgesetzt (pre-existing)                   |
| R-005 | Unmaskierter stdout bei Erfolg | Wichtig     | Nicht umgesetzt (by-design)                      |
| R-006 | Fehlender Edge-Case-Test       | Hinweis     | Behoben                                          |
| R-007 | Recipe-Fehler ohne Modulname   | Hinweis     | Nicht umgesetzt (pre-existing)                   |
