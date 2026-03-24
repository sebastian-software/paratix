# 0070: User-focused README entrypoints

## Anforderung

Die Einstiegsdokumentation soll auf den aktuellen Stand gebracht und konsequent aus Sicht eines Nutzers von Paratix umgeschrieben werden.

Betroffen sind:

- Root-README als Einstieg über GitHub
- `packages/paratix/README.md` als Einstieg über npm für das eigentliche Tool
- `packages/create-paratix/README.md` als Einstieg über npm für das Scaffold

Jede README soll mit einer kurzen Marketing-Einführung starten, danach Features, dann Nutzung/Getting Started und am Ende Lizenz/Copyright enthalten.

## Architekturentscheidungen

- Die Root-README wird als Produkt- und Repo-Einstieg positioniert, nicht als Monorepo-Referenz.
- Die Paket-READMEs werden auf ihren jeweiligen Nutzungskontext zugeschnitten:
  - `paratix`: Tool-/CLI-Einstieg
  - `create-paratix`: Scaffold-/Bootstrap-Einstieg
- Tiefe API- und Modulreferenzen werden aus den Einstiegs-READMEs reduziert und durch klare Nutzerführung ersetzt.
- Die Dokumentationssprache bleibt Englisch, weil die bestehenden READMEs bereits englisch sind.

## Betroffene Dateien

| Datei                                                                                      | Beschreibung                                              |
| ------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| [README.md](/Users/bs5/Developer/sebastian-gmbh-paratix/README.md)                         | Neu als GitHub-Einstieg mit Produktfokus strukturiert     |
| [README.md](/Users/bs5/Developer/sebastian-gmbh-paratix/packages/paratix/README.md)        | Neu als npm-Einstieg für das `paratix`-Paket strukturiert |
| [README.md](/Users/bs5/Developer/sebastian-gmbh-paratix/packages/create-paratix/README.md) | Neu als npm-Einstieg für das Scaffold-Paket strukturiert  |

## Implementierungsdetails

- Kurze Marketing-Einleitung in 2-3 Absätzen am Anfang jeder README
- Danach klare Feature-Abschnitte mit Nutzerwert statt interner Struktur
- Danach praktische Nutzung/Getting Started mit aktuellem Produktstand
- Lizenz und Copyright unverändert am Ende

## Testergebnisse

- `pnpm agent:check`

## Review-Findings und Behebung

- Keine zusätzlichen Review-Findings in diesem Doku-Feature
