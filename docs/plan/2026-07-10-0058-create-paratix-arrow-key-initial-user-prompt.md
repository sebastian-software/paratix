# 0058: create-paratix Arrow-Key Initial User Prompt

## Anforderung

Der interaktive Prompt von `create-paratix` soll die Initial-User-Frage verständlicher erklären und die Auswahl zwischen Root- und Admin-Start per Cursor-Tasten erlauben.

## Architekturentscheidungen

- Keine neue externe Prompt-Abhängigkeit: Die Auswahl wird mit einer kleinen lokalen TTY-Select-Implementierung in `packages/create-paratix/src/index.ts` umgesetzt.
- Der nicht-interaktive Vertrag über `--initial-user <root|name>` bleibt unverändert bestehen.
- Die bestehende Texteingabe für den konkreten Admin-User bleibt erhalten und wird nur nach der Select-Auswahl verwendet.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                           |
| -------------------------------------------- | ---------------------------------------------------------------------- |
| `packages/create-paratix/src/index.ts`       | Erklärende Select-Auswahl mit Pfeiltasten für den Initial-User ergänzt |
| `packages/create-paratix/test/index.test.ts` | Interaktive Root-/Admin-Flows auf den neuen Select-Vertrag umgestellt  |
| `packages/create-paratix/README.md`          | Prompt-Verhalten und Auswahlpfade dokumentiert                         |

## Implementierungsdetails

- Neue lokale Select-UI mit `emitKeypressEvents`, Raw-Mode und Enter-Bestätigung.
- Erklärende Auswahlfrage: welcher SSH-User für die erste Verbindung bereits funktioniert.
- Zwei klar beschriebene Optionen:
  - `Root user`
  - `Admin user`
- Bei Auswahl von `Admin user` folgt weiter die Texteingabe für den konkreten Usernamen.

## Testergebnisse

- `pnpm --filter create-paratix test`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen Findings aus der Implementierung.
