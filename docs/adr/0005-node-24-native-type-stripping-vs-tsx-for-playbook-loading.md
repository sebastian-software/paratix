# 0005 — Node-24-natives Type-Stripping vs. tsx für Playbook-Loading

## Status

Angenommen — ADR-only, kein Produktiv-Swap in diesem Schritt. Der nativ-first-Loader ist als Folgeschritt vorbereitet und wird erst mit grüner Integrationssuite scharfgeschaltet.

## Kontext

Issue: sebastian-software/paratix#84
Epic: sebastian-software/paratix#97

`paratix` zieht `tsx` (`^4.22.3`) als **Produktions-Dependency**. `tsx` benötigt zur Laufzeit `esbuild` (`~0.28.0`) inklusive plattformspezifischer Binaries. Zur Laufzeit wird `tsx` an genau einer Stelle genutzt: `packages/paratix/src/cli.ts:569` importiert `tsx/esm/api` lazy und ruft `register()`, um `.ts`/`.mts`/`.cts`-Playbooks per globalem ESM-Loader-Hook ladbar zu machen (`loadServerDefinitionFromFile`, `registerTsxForTypeScriptEntry`).

`paratix` verlangt bereits `engines.node >= 24.0.0`. Node hat natives Type-Stripping für `.ts`-Dateien seit v22.18.0 / v23.6.0 standardmäßig aktiv (`--experimental-strip-types` ist per Default eingeschaltet, `--no-strip-types` deaktiviert es). Für alle von `paratix` unterstützten Runtimes (>= 24) ist natives Stripping also ohne Flag verfügbar. `--experimental-transform-types` (für nicht-erasable Syntax wie `enum`/`namespace`) bleibt opt-in.

Damit stellt sich die Frage: Kann natives Stripping `tsx` beim Laden scaffoldeter Playbooks ersetzen und so den ~20-MB-esbuild-Fußabdruck aus jeder `paratix`-Installation entfernen?

## Analyse

### Was `pnpm create paratix` generiert

- `packages/create-paratix/src/templates.ts` erzeugt genau eine `server.ts` pro Projekt (Root-Bootstrap- oder Admin-Variante).
- Der generierte Code nutzt **ausschließlich erasable Syntax**: bare-specifier-Imports (`import { … } from "paratix"`, `… from "paratix/modules"`), `const`-Deklarationen, Objektliterale und Funktionsaufrufe. Es kommen **keine** Typannotationen, `enum`s, `namespace`s, Decorators, Parameter-Properties oder relativen `.ts`-Importe vor.
- Der generierte `tsconfig.json` (`TSCONFIG_TEMPLATE`) verwendet `moduleResolution: "Bundler"`, aber **kein** `paths`-Mapping — es gibt also keine Alias-Auflösung, die zur Laufzeit ohnehin weder von nativem Stripping noch von `tsx` erfüllt würde.
- Das generierte `package.json` (`scaffoldFiles.ts`) listet `tsx` weiterhin als devDependency des Zielprojekts (neben `typescript`, `eslint`, `prettier`), unabhängig von der `paratix`-Prod-Dependency.

### Praktische Verifikation (Node 26.3.1, dieser Worktree)

Beide real gerenderten Template-Varianten wurden mit einem Stub-`paratix`-Paket **ohne `tsx` und ohne Flags** nativ importiert:

- Root-Variante: `import()` erfolgreich, `default.run` mit 11 Modulen.
- Admin-Variante: `import()` erfolgreich, `default.run` mit 10 Modulen.
- Gegenprobe mit `--no-strip-types`: `ERR_UNKNOWN_FILE_EXTENSION` für `.ts` — bestätigt, dass das native Stripping der aktivierende Mechanismus ist.
- `templates.ts` selbst (mit Union-Typen und Typannotationen) wird ebenfalls nativ gestrippt und ausgeführt.

**Ergebnis: Scaffoldete Playbooks sind mit nativem Type-Stripping voll kompatibel.**

### Grenzen des nativen Strippings (belegt)

Native Stripping-Mode lehnt Syntax ab, die `tsx` (esbuild) transformiert:

- `enum` → `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` (zuverlässiger, eindeutiger Diskriminator).
- extensionsloser relativer Import (`import … from "./dep"`) → `ERR_MODULE_NOT_FOUND`.
- `.js`-Specifier, der auf `./dep.ts` zeigt (`import … from "./dep.js"`) → `ERR_MODULE_NOT_FOUND`.

Die beiden `ERR_MODULE_NOT_FOUND`-Fälle sind **nicht** eindeutig von einer echt fehlenden Dependency (Tippfehler, nicht installiertes npm-Paket) unterscheidbar.

### Fallback-Mechanik (belegt, Node 26.3.1)

Getestet wurde „nativ zuerst, bei Fehler `tsx.register()` und erneuter `import()` derselben URL":

- `enum.ts`: nativ scheitert mit `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`, Retry nach `tsx.register()` **erfolgreich** (Node cached den Compile-Fehler nicht).
- `.js`→`.ts`-Import: nativ scheitert mit `ERR_MODULE_NOT_FOUND`, Retry nach `tsx.register()` **erfolgreich**.

Mechanisch funktioniert der nativ-first-Loader mit `tsx`-Fallback auf Node 26 also für beide Fehlerklassen.

### Fußabdruck-Messung (dieser Worktree, pnpm-Store)

| Artefakt                                           | Größe                         |
| -------------------------------------------------- | ----------------------------- |
| `tsx@4.22.4`                                       | 668 KB                        |
| `esbuild@0.28.1` (JS)                              | ~10 MB                        |
| `@esbuild/darwin-arm64@0.28.1` (Plattform-Binary)  | ~10 MB                        |
| **`tsx`-Laufzeit-Closure gesamt (eine Plattform)** | **~20,6 MB pro Installation** |

Dieser Betrag wird aktuell in **jede** `paratix`-Installation als Prod-Dependency gezogen. Der Fußabdruck-Gewinn entsteht **nur**, wenn `tsx` entfernt oder nach `optionalDependencies` verschoben wird. Bleibt `tsx` verpflichtender Fallback, ist der Gewinn null.

## Entscheidung

1. Die Machbarkeit ist für den Default-Fall belegt: **natives Stripping trägt scaffoldete Playbooks vollständig** (kein `tsx`, kein Flag, Node >= 24).
2. In diesem Schritt erfolgt **keine Produktiv-Codeänderung** am Playbook-Loading und **keine** Änderung der `paratix`-Dependencies.
3. Der nativ-first-Loader wird als Folgeschritt vorbereitet und **erst mit grüner Integrationssuite** scharfgeschaltet — diese ist laut Issue #84 der eigentliche Gate und war in dieser Umgebung mangels Docker/Colima nicht ausführbar.

## Begründung

Playbook-Loading ist ein sicherheits- und zuverlässigkeitsrelevanter Kern. Trotz belegter Machbarkeit bleiben Risiken, die **ausschließlich** über die Docker-gestützte Integrationssuite abgesichert werden können und lokal (`pnpm agent:check`, Unit-/dist-Tests) nicht abschließend beweisbar sind:

- **Node-24-Floor ungetestet:** Alle Messungen liefen auf Node 26.3.1. Die unterstützte Untergrenze ist Node 24. Modul-Cache-Verhalten bei fehlgeschlagenem Load und Stripping-Details variieren historisch zwischen Node-Minors; die Fallback-Recovery muss auf Node 24.x real bestätigt werden.
- **Fehler-Maskierung auf dem `ERR_MODULE_NOT_FOUND`-Pfad:** Ein Fallback bei `ERR_MODULE_NOT_FOUND` kann eine echt fehlende Dependency hinter einem `tsx`-Retry verbergen. Ist `tsx` (als optionale Dependency) nicht installiert, erhält der Nutzer die irreführende „install tsx"-Meldung (`handleTsxLoadFailure`) statt der korrekten „module not found"-Diagnose. Eine engere Variante (Fallback nur bei `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`) vermeidet das, verschiebt aber extensionslose und `.js`→`.ts`-Importe zu harten Fehlern.
- **Doppelte Top-Level-Ausführung:** Schlägt ein nativer Import erst nach teilweiser Modulgraph-Auswertung fehl, führt der `tsx`-Retry seiteneffektbehafteten Top-Level-Code erneut aus. Playbooks sind überwiegend deklarativ (`server({…})`), enthalten aber Top-Level-Statements (z. B. `isFirstRun()`), sodass Doppelausführung nicht ohne E2E-Abdeckung ausgeschlossen werden kann.
- **Der eigentliche Gate fehlt hier:** Ohne die Integrationssuite lässt sich ein Swap im Kern-Loading-Pfad nicht zweifelsfrei absichern. Die konservative Regel für diesen Kern lautet: im Zweifel kein Scharfschalten.

Da der Fußabdruck-Gewinn zwingend an `tsx → optionalDependencies` gekoppelt ist und genau diese Änderung den Kern-Loading-Pfad und dessen Fehlerpfad berührt, wäre ein Swap ohne grüne Integrationssuite unverantwortlich. Die Machbarkeit ist belegt; die Freigabe ist es noch nicht.

## Empfohlener Folgeschritt (mit Integrations-Gate scharfzuschalten)

1. In `loadServerDefinitionFromFile`/`registerTsxForTypeScriptEntry`: für TypeScript-Entries zuerst **nativ** `import(fileUrl)` versuchen, `tsx` **nicht** vorab registrieren.
2. Fallback konservativ nur bei `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` (eindeutiger Diskriminator): `tsx.register()` und einmaliger Retry derselben `fileUrl`. `ERR_MODULE_NOT_FOUND` bleibt zunächst ein harter, ehrlicher Fehler, um Diagnose-Maskierung zu vermeiden; eine Erweiterung auf extensionslose/`.js`→`.ts`-Importe erst nach expliziter Integrationsabdeckung.
3. `tsx` von `dependencies` nach `optionalDependencies` in `packages/paratix/package.json` verschieben; der bestehende `isMissingTsxDependencyError`/`handleTsxLoadFailure`-Pfad deckt die „tsx nicht installiert"-Meldung bereits ab.
4. Gate: `agent:check:integration` (Docker/Colima) grün auf Node 24.x **und** Node 26.x, inklusive Szenarien für scaffoldete Playbooks, `enum`-Fallback und fehlende-Dependency-Diagnose. Fußabdruck vorher/nachher erneut messen und dokumentieren.

## Quelle

- Issue sebastian-software/paratix#84 — tsx durch Node-24-natives Type-Stripping ersetzen (Prod-`esbuild` ~10 MB entfernen).
- Epic sebastian-software/paratix#97.
- Laufzeitnutzung: `packages/paratix/src/cli.ts:569` (`import("tsx/esm/api")`), `loadServerDefinitionFromFile` / `registerTsxForTypeScriptEntry`.
- Scaffold: `packages/create-paratix/src/templates.ts`, `packages/create-paratix/src/scaffoldFiles.ts`.
