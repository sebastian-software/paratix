# 0034: Shutdown Signal Module Loop Test

## Anforderung

Test schreiben, der beweist: Bei 2 Modulen und SIGINT während Modul 1 wird Modul 2
nicht gestartet — über den `shutdownSignal()`-Check am Schleifen-Anfang, nicht über
einen SSH-Fehler.

## Kontext

Das vorherige Refactoring (0031) hat einen `shutdownSignal()`-Check am Anfang der
`for`-Schleife in `runModuleLoop` eingefügt (runner.ts:292). Der bestehende Test in
Zeile 514 testet einen ähnlichen Fall, aber dort wird der Abbruch über einen
SSH-Reconnect-Fehler (`shouldBreak: true`) ausgelöst, nicht über den
`shutdownSignal()`-Check.

## Implementierung

### Betroffene Datei

- `packages/paratix/test/runner.test.ts` — neuer `it()`-Block im bestehenden
  `describe("runPlaybook signal handling")`

### Test-Mechanik

1. Modul 1: `apply()` emittiert SIGINT via `process.emit()` und gibt erfolgreich
   `{ status: "changed" }` zurück (kein Fehler, kein `shouldBreak`)
2. Modul 2: `check` und `apply` als `vi.fn()` — dürfen nie aufgerufen werden
3. Der Loop kehrt nach Modul 1 zurück, `shouldBreak` ist `false`, aber der
   `shutdownSignal()`-Check am nächsten Iterationsstart greift → `break`

### Assertions

- `module1.apply` wurde einmal aufgerufen (Modul 1 lief durch)
- `module2.check` wurde nie aufgerufen (Modul 2 wurde nicht gestartet)
- `process.exitCode === 130` (SIGINT-Exitcode)
- `disconnectFn` wurde aufgerufen (SSH getrennt)

## Testergebnisse

- 981 Tests bestanden (962 paratix + 19 create-paratix), 0 fehlgeschlagen
- 0 TypeScript-Fehler, 0 Lint-Fehler, Build erfolgreich

## Review-Findings

Keine kritischen oder wichtigen Findings. 2 Hinweise (optionale Verbesserungen):

1. Kommentar zur Abgrenzung vom ähnlichen Test in Zeile 452
2. Zusätzliche `module2.apply` Assertion
