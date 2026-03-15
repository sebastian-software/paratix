# 0032 Test: SIGINT während reconnect() bricht Module-Loop ab

## Anforderung

Test hinzufügen, der SIGINT während `reconnect()` simuliert und prüft, dass die Module-Loop abbricht und der korrekte Signal-Exit-Code (130) gesetzt wird.

## Architekturentscheidungen

- **Nur Test-Code**: Kein Produktionscode geändert. Der Test validiert bestehendes Verhalten.
- **Neue Factory-Funktion**: `makeMockSshClassWithReconnectSignal` erstellt Mock-SSH-Klasse deren `reconnect()` synchron SIGINT emittiert und dann einen Error wirft — simuliert den Fall, dass ein Signal den Reconnect-Versuch unterbricht.
- **Platzierung in bestehender describe-Sektion**: Test wurde in `describe("runPlaybook signal handling")` eingefügt, da er thematisch zur Signal-Behandlung gehört.

## Betroffene Dateien

### packages/paratix/test/runner.test.ts

- `makeMockSshClassWithReconnectSignal(configs, disconnectMock)`: Factory für Mock-SSH mit SIGINT-emittierendem `reconnect()`
- Neuer Test: "aborts the module loop and sets exitCode to 130 when SIGINT is received during reconnect"

## Testlogik

1. Mock-SSH mit `reconnect()` das `process.emit("SIGINT")` feuert und dann Error wirft
2. Modul A gibt `meta: { "sshd.port": "2222" }` zurück → triggert `handlePortChange()` → `reconnect()`
3. SIGINT setzt `receivedSignal` im Shutdown-Handler
4. Error propagiert: `handlePortChange` → `handleMetaAndBuildResult` → `runRegularModule` catch → `shouldBreak: true`
5. Module-Loop bricht ab, Modul B läuft nicht

### Assertions

- `process.exitCode === 130` (Signal-Exit-Code hat Priorität über failed=1)
- `moduleWithPortChange.apply` wurde aufgerufen (apply-Pfad wurde durchlaufen)
- `subsequentModule.check` wurde **nicht** aufgerufen (Loop abgebrochen)
- `disconnectFn` wurde aufgerufen (Signal-Handler hat disconnect getriggert)

## Review-Findings

| Schweregrad | Anzahl | Behoben | Offen |
| ----------- | ------ | ------- | ----- |
| Kritisch    | 0      | 0       | 0     |
| Wichtig     | 2      | 0       | 2     |
| Hinweis     | 2      | 1       | 1     |

### Offene Findings

1. **Factory-Duplikation** (Wichtig): Vier Mock-SSH-Factories mit nahezu identischem Code. Vorbestehendes Problem, nicht durch diese Änderung verursacht.
2. **Testname-Präzision** (Wichtig): Testname könnte präziser sein, aber inline-Kommentar dokumentiert den Sachverhalt.
3. **Inkonsistente Factory-Platzierung** (Hinweis): Globale Factory wird nur in einem describe-Block verwendet.

### Behobene Findings

4. **Fehlende Apply-Assertion** (Hinweis): `expect(moduleWithPortChange.apply).toHaveBeenCalledOnce()` hinzugefügt.

## Testergebnisse

- 866 Tests bestanden (1 neuer)
- 0 neue Lint/Type/Format-Fehler
