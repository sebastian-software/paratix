# Plan 0086: create-paratix Runtime-Dependency-Range ableiten

## Anforderung

`create-paratix` soll beim Scaffolding keine veraltete, hartcodierte `paratix`-Runtime-Version installieren. Die generierte Dependency-Range muss aus der Release-Quelle des Scaffolders abgeleitet werden, damit Release-Please-Versionierungen automatisch in neue Projekte einfließen.

## Architekturentscheidungen

- Die `paratix`-Dependency-Range wird zur Laufzeit aus der `version` von `packages/create-paratix/package.json` abgeleitet.
- Die Versionsquelle liegt im npm-Paket weiterhin am erwarteten Ort: `package.json` wird von npm unabhängig von der `files`-Liste mit ausgeliefert.
- Die Ableitung validiert die Package-Version als Semver, bevor daraus eine Caret-Range erzeugt wird. Dadurch scheitert ein beschädigtes Paket früh statt ein ungültiges Scaffold auszugeben.
- `release-please-config.json` und `.release-please-manifest.json` bleiben unverändert, weil die bestehende Linked-Version-Konfiguration bereits `paratix` und `create-paratix` koppelt.

## Betroffene Dateien

| Datei                                                       | Beschreibung                                                                |
| ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| `packages/create-paratix/src/dependencyRange.ts`            | Neue Runtime-Ableitung und Semver-Validierung der Scaffold-Dependency-Range |
| `packages/create-paratix/src/index.ts`                      | Verwendet die abgeleitete Range beim Schreiben der Projekt-`package.json`   |
| `packages/create-paratix/test/index.test.ts`                | Regressionstest gegen die aktuelle `create-paratix`-Package-Version         |
| `docs/plan/0086-create-paratix-runtime-dependency-range.md` | Abschlussdokumentation des Workflows                                        |

## Implementierungsdetails

- `deriveParatixDependencyRange()` liest `../package.json` relativ zu `import.meta.url`. Das funktioniert sowohl aus `src/` im Testlauf als auch aus `dist/` nach dem Build.
- Die Semver-Prüfung ist bewusst ohne komplexe Regex implementiert, damit die vorhandenen Security-Lint-Regeln sauber bleiben.
- `writeProjectFiles()` ruft die Ableitung beim Erzeugen der Scaffold-`package.json` auf und schreibt `dependencies.paratix` als `^<create-paratix version>`.
- Der bestehende Test für die generierte `paratix`-Dependency vergleicht nicht mehr mit einer festen Version, sondern mit der aktuellen Version aus `packages/create-paratix/package.json`.

## Testergebnisse

- `pnpm --filter create-paratix test` – bestanden, 162 Tests
- `node -e "import('./packages/create-paratix/dist/index.js').then((m)=>console.log(m.deriveParatixDependencyRange()))"` – bestanden, Ausgabe `^0.10.0`
- `pnpm agent:check` – bestanden

## Review-Findings

**Datum:** 2026-05-05
**Reviewer:** keiner

Kein separater Reviewer gestartet; die Änderung ist eng begrenzt, vollständig durch fokussierte Tests und `pnpm agent:check` validiert.
