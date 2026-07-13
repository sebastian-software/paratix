# 0057: `--first-run`-Flag für Paratix CLI

## Anforderung

Paratix soll einen CLI-Parameter `--first-run` erhalten, der speziell für von `create-paratix` erzeugte Projekte den Bootstrap-Flag aktiviert. Das generierte Scaffold soll dazu den Erstlauf-Zustand aus `process.env.PARATIX_FIRST_RUN` lesen und dokumentieren, dass der erste Lauf mit `--first-run`, spätere Läufe dagegen ohne diesen Flag ausgeführt werden.

## Architekturentscheidungen

- Die Paratix-CLI setzt bei `--first-run` vor dem dynamischen Playbook-Import `process.env.PARATIX_FIRST_RUN = "true"`.
- Zusätzlich wird derselbe Wert in die CLI-`envOverrides` übernommen, damit der Bootstrap-Zustand auch im normalen Environment-Merge sichtbar bleibt.
- Das von `create-paratix` erzeugte `server.ts` liest den lokalen `FIRST_RUN`-Boolean ausschließlich aus `process.env.PARATIX_FIRST_RUN === "true"`.
- Der Scaffold-Default ist damit ohne Flag der reguläre Folgezustand; der Bootstrap wird bewusst nur über `--first-run` aktiviert.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                             |
| -------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `packages/paratix/src/cli.ts`                | Fügt `--first-run` hinzu und setzt `PARATIX_FIRST_RUN` vor dem Playbook-Import           |
| `packages/paratix/test/cli.test.ts`          | Prüft Environment-Override, Prozess-Environment und den CLI-Entrypoint mit `--first-run` |
| `packages/create-paratix/src/templates.ts`   | Lässt das generierte Scaffold `FIRST_RUN` aus `process.env.PARATIX_FIRST_RUN` ableiten   |
| `packages/create-paratix/test/index.test.ts` | Aktualisiert Scaffold-Regressionstests auf die neue `PARATIX_FIRST_RUN`-Quelle           |
| `packages/create-paratix/README.md`          | Dokumentiert den Bootstrap-Ablauf: erster Lauf mit `--first-run`, spätere ohne           |

## Implementierungsdetails

- `--first-run` ist bewusst ein semantischer Shortcut statt eines generischen Env-Mutators.
- Der Flag wirkt schon beim Playbook-Import, damit das generierte Scaffold damit auch `ssh.ports` und `strictHostKeyChecking` steuern kann.
- Das Scaffold behält weiterhin den lokalen Namen `FIRST_RUN` für die abgeleiteten Konstanten, aber die Quelle ist nun `process.env["PARATIX_FIRST_RUN"]`.
- Die README verweist explizit auf `paratix apply ... --first-run` für den Bootstrap und auf normale Aufrufe ohne Flag für spätere Läufe.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/cli.test.ts`
- `pnpm --filter create-paratix exec vitest run test/index.test.ts`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen internen Review-Findings nach der Umsetzung.
