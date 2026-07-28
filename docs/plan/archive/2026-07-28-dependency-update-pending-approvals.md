# Umfassendes Dependency-Update der Renovate Pending Approvals

**Planungsstatus:** Umgesetzt
**Quelle:** /effective-flow plan
**Empfohlener Workflow:** Refactoring (`/effective-flow refactor`)

## Anforderung

Das Renovate Dependency Dashboard (Issue #58) listet 17 Einträge unter „Pending Approval“. Keiner
davon ist bisher als Branch oder PR angelegt, weil die Renovate-Konfiguration
(`local>sebastian-software/renovate-config`) eine manuelle Freigabe verlangt. Ziel ist ein
vollständiges, gestaffeltes Update aller 17 Einträge — inklusive der vier Major-Sprünge — mit
belegten Breaking Changes aus den jeweiligen Changelogs statt blinder Versionsanhebung.

Der Plan wird nicht über die Dashboard-Checkboxen ausgeführt, sondern manuell in fünf Batches. Grund:
drei der Einträge erfordern begleitende Code- oder Konfigurationsänderungen, die Renovate nicht
erzeugen kann (Icon-Renames, React-Router-Future-Flags, TypeScript-Side-by-side-Setup). Die
Dashboard-Einträge verschwinden automatisch, sobald die Zielversionen im Repository stehen.

Der operative Einstieg für die einzelne Batch-Umsetzung ist `/effective-flow maintain`; die
Workflow-Kategorie des Plans ist `Refactoring`, weil das Produktverhalten unverändert bleibt.

### Bestandsaufnahme

Installierter Stand (aus `pnpm ls -r`, Stand 2026-07-28) gegen die von Renovate vorgeschlagenen
Zielversionen. Die 17 Dashboard-Einträge verdichten sich hier auf 15 Zeilen: `react` und
`react-dom` sind zwei Einträge in einer Zeile, und `lucide-react` erscheint im Dashboard zweimal
(`^0.577.0` und `v1`), wird hier aber auf ein Ziel zusammengezogen.

| Paket                                             | Installiert | Ziel    | Einstufung                        |
| ------------------------------------------------- | ----------- | ------- | --------------------------------- |
| `pnpm` (`packageManager`)                         | 11.5.3      | 11.17.0 | Minor-Serie                       |
| `@types/node` (3 Manifeste)                       | 24.13.2     | 24.13.3 | Patch                             |
| `concurrently`                                    | 10.0.3      | 10.0.4  | Patch                             |
| `isbot`                                           | 5.2.0       | 5.2.1   | Patch                             |
| `tsx`                                             | 4.22.4      | 4.23.1  | Minor                             |
| `vitest` / `@vitest/coverage-v8`                  | 4.1.9       | 4.1.10  | Patch                             |
| `react` / `react-dom`                             | 19.2.4      | 19.2.8  | Patch                             |
| `eslint`                                          | 10.6.0      | 10.8.0  | Minor                             |
| `eslint-config-setup`                             | 0.4.0       | ^0.5.2  | Minor auf 0.x — verhaltensändernd |
| `oxlint`                                          | 1.72.0      | ^1.76.0 | Minor                             |
| `prettier`                                        | 3.8.4       | 3.9.6   | Minor — Formatierung ändert sich  |
| `lucide-react`                                    | 0.468.0     | ^1.27.0 | Major — Exporte entfernt          |
| `react-router` + `@react-router/{dev,node,serve}` | 7.18.1      | 8.3.0   | Major                             |
| `vite` (Website)                                  | 7.3.6       | ^8.1.5  | Major                             |
| `typescript`                                      | 6.0.3       | 7.0.2   | Major — kein Compiler-API         |

### Belegte Breaking Changes

**TypeScript 7** (Release-Blog vom 2026-07-08): Der Go-Port liefert in 7.0 **keine programmatische
API**; diese kommt erst mit 7.1. `typescript-eslint@8.65.0` deklariert den Peer
`typescript: ">=4.8.4 <6.1.0"` und importiert `typescript` direkt — ein reiner Sprung auf 7.0 würde
die typbewussten Regeln (`@typescript-eslint/no-unsafe-argument`,
`@typescript-eslint/no-unsafe-type-assertion`, beide in `eslint.config.ts` referenziert) und die
`dts`-Erzeugung von `tsup` brechen. Microsoft empfiehlt dafür ausdrücklich den npm-Alias-Betrieb von
7.0 neben 6.0. Zusätzlich gilt:

- `ignoreDeprecations` wird als Option nicht mehr akzeptiert. `tsconfig.json` setzt aktuell
  `"ignoreDeprecations": "6.0"` (eingeführt in `bd7a4911`).
- `types` hat den neuen Default `[]`. `packages/paratix/tsconfig.json` und
  `packages/create-paratix/tsconfig.json` setzen `types` nicht und erben von `tsconfig.json`, das
  es ebenfalls nicht setzt. In `packages/paratix/src` nutzen 25 Dateien `process.`, 22 Dateien
  `Buffer` und 9 Dateien `setTimeout` — alles Globals aus `@types/node`.
- `rootDir` hat den neuen Default `./`. Beide Paket-`tsconfig.json` setzen `rootDir` bereits
  explizit; `tsconfig.root.json`, `scripts/tsconfig.json` und `website/tsconfig.json` laufen mit
  `noEmit`. Hier besteht kein Handlungsbedarf.
- Die JS-/JSDoc-Analyse wurde umgebaut (Closure-Syntax, `@enum`, `@class`, Postfix-`!` entfallen).
  `scripts/*.mjs` enthält keine JSDoc-Typannotationen, `scripts/tsconfig.json` setzt bereits
  `types: ["node"]` — Risiko damit gering.
- `esModuleInterop: false` und `alwaysStrict: false` sind harte Fehler; das Repo setzt beides nicht
  auf `false`. `moduleResolution: NodeNext`/`Bundler` bleiben unterstützt.

**React Router 8** (offizieller Upgrade-Guide): Mindestversionen `node@22.22+` und
`react@19.2.7+`/`react-dom@19.2.7+` — React 19.2.8 ist damit eine harte Voraussetzung. Framework Mode
verlangt `vite@7+` **und** das Future-Flag `v8_viteEnvironmentApi`. Weitere Breaking Changes:
`meta`/`matches`-Feld `data` → `loaderData`, Entfall von `react-router-dom`, Entfall des
Cloudflare-Dev-Proxys. Prüfung des Website-Codes: `website/app/routes/home.tsx` exportiert `meta`
ohne Argumente, es gibt keinen Loader, kein `useMatches`, keinen `react-router-dom`-Import, keinen
Custom Server und keine Cloudflare-Nutzung. Von den fünf Future-Flags ist nur
`v8_viteEnvironmentApi` funktional relevant; die übrigen vier sind hier gegen den Website-Code als
folgenlos nachgewiesen:

| Flag                                | Wirkt auf                                      | Befund für diese Website                             |
| ----------------------------------- | ---------------------------------------------- | ---------------------------------------------------- |
| `v8_viteEnvironmentApi`             | Custom `isSsrBuild`-`rollupOptions`            | keine vorhanden; Flag dennoch verpflichtend          |
| `v8_middleware`                     | Custom Server mit `getLoadContext`             | nutzt `react-router-serve`, laut Guide ohne Änderung |
| `v8_splitRouteModules`              | Client-Chunking                                | laut Guide ohne Codeänderung                         |
| `v8_passThroughRequests`            | `request.url`-Auswertung in Loadern            | keine Loader vorhanden                               |
| `v8_trailingSlashAwareDataRequests` | eigene `.data`-Rewrite-, CDN- oder Cache-Logik | keine vorhanden; Prerender nur `/`                   |

**Vite 8** (offizieller Migration-Guide): Rolldown und Oxc ersetzen Rollup und esbuild. Relevant sind
der neue Default-Browser-Target (Chrome 111, Firefox 114, Safari 16.4), die vereinheitlichte
CommonJS-`default`-Interop, esbuild als nur noch optionale Abhängigkeit und die Umbenennung
`build.rollupOptions` → `build.rolldownOptions`. `website/vite.config.ts` enthält nur
`plugins: [reactRouter()]` und keine dieser Optionen. `@react-router/dev@7.18.1` deklariert bereits
`vite: "^5 || ^6 || ^7 || ^8"`, Vite 8 ist also nicht an React Router 8 gekoppelt — Vite 8.0.16 liegt
über die Vitest-Kette ohnehin schon im Lockfile.

**lucide-react 1.x**: Die Nummern-Aliase sind entfernt. Gegen die Typdeklarationen von
`lucide-react@1.27.0` verifiziert — und identisch bereits in `0.577.0`, der Minor-Sprung ist also
genauso brechend wie der Major:

| Entfernt         | Ersatz           | Vorkommen in `website/app/routes/home.tsx` |
| ---------------- | ---------------- | ------------------------------------------ |
| `Code2`          | `CodeXml`        | 2                                          |
| `Layers3`        | `Layers`         | 2                                          |
| `CheckCircle2`   | `CircleCheckBig` | 10                                         |
| `TerminalSquare` | `SquareTerminal` | 2                                          |

**Prettier 3.9**: Der Markdown-Parser wechselt von `remark-parse` v8 auf `micromark` v4, der
YAML-Parser auf `yaml` v2, dazu kommen mehrere TypeScript-Formatierungskorrekturen. Das Repository
hat 133 von Prettier erfasste Markdown-Dateien (`.prettierignore` schließt nur `CHANGELOG.md`,
`renovate.json` und `pnpm-lock.yaml` aus) und 8 YAML-Dateien. `pnpm format:check` wird nach dem
Update mit hoher Wahrscheinlichkeit fehlschlagen, bis ein Repo-weiter `pnpm format` gelaufen ist.

**eslint-config-setup 0.5**: Das Release 0.5.0 enthält den Commit „migrate react lint strategy“. Der
Abhängigkeitsvergleich 0.4.0 → 0.5.2 zeigt `@eslint-react/eslint-plugin` 4 → 5,
`eslint-plugin-unicorn` 64 → 71, `eslint-plugin-n` 17 → 18, `eslint-plugin-package-json` 0.91 → 1.5,
`@eslint/json` 1 → 2 sowie die neu hinzugekommenen `eslint-plugin-react-perf` und
`eslint-plugin-react-you-might-not-need-an-effect`. Der Peer steigt auf `eslint: ">=10"`. Da
`lint:eslint` mit `--max-warnings=0` läuft, führen neue oder verschärfte Regeln direkt zu einem
roten Check. 0.5.2 enthält zusätzlich den Sicherheits-Pin „pin esbuild to patched version“.

**pnpm 11.17**: Reine Minor- und Patch-Releases ohne Breaking Change, darunter mehrere
Sicherheitskorrekturen (Path-Traversal beim Linking, `adm-zip`, Speicherbegrenzung beim
Auth-Token-Poll). `updateConfig`/`auditConfig` werden durch `update`/`audit` in
`pnpm-workspace.yaml` abgelöst; das Repository nutzt keinen der beiden Schlüssel.

**Unkritisch:** `vitest` 4.1.10 (zwei Bugfixes), `concurrently` 10.0.4 (`shell-quote`-Bump,
Kill-Timeout-Fix), `tsx` 4.23.1 (Resolver-Performance), `isbot` 5.2.1, `@types/node` 24.13.3,
`react`/`react-dom` 19.2.5–19.2.8 (ausschließlich React-Server-Components-Korrekturen; die Website
nutzt keine RSC).

## Architekturentscheidungen

- **Fünf thematische Batches statt eines Sammel-PRs.** Vier der Updates können den `agent:check` aus
  völlig unterschiedlichen Gründen brechen (Rolldown-Bundling, neue Lint-Regeln, Icon-Exporte,
  Compiler-Wechsel). Getrennte Branches halten die Ursache lokalisierbar und jeden Batch einzeln
  zurücknehmbar.
- **TypeScript 7 im Side-by-side-Betrieb mit TypeScript 6.** Entscheidung des Auftraggebers, gestützt
  auf die im TypeScript-7.0-Blog beschriebene Best Practice: `typescript` wird per npm-Alias auf
  `@typescript/typescript6` gelegt (bedient die Compiler-API-Konsumenten typescript-eslint und tsup),
  `@typescript/native` per Alias auf `typescript@7` (liefert das `tsc`-Binary für die
  Typecheck-Skripte). Die Alternative — Zurückstellen bis TypeScript 7.1 — wurde verworfen, weil der
  Geschwindigkeitsgewinn im `agent:check` sofort wirkt.
- **`lucide-react` direkt auf `^1.27.0`, der Zwischenschritt `^0.577.0` entfällt.** Beide Versionen
  erfordern exakt dieselben vier Icon-Renames; ein Zwischenschritt erzeugt zusätzliche
  Review-Runden ohne Erkenntnisgewinn.
- **Vite 8 zusammen mit React Router 8 in einem Batch.** Technisch wären beide entkoppelbar, aber der
  Website-Build ist mit einer einzigen Route und einem Prerender-Test so klein, dass die gemeinsame
  Verifikation billiger ist als zwei Runden. Ein Fehlschlag ist über die getrennten Commits innerhalb
  des Batches trotzdem zuzuordnen.
- **Prettier-Update und Repo-weiter Reformat in getrennten Commits.** Der Reformat-Diff über 133
  Markdown-Dateien darf den inhaltlichen Teil des Batches nicht überdecken.
- **Streng sequenzielle Auslieferung: ein PR pro Batch, der nächste Branch entsteht erst nach dem
  Merge des Vorgängers.** Jeder Batch schreibt `pnpm-lock.yaml`; gleichzeitig offene PRs auf
  `origin/main` würden dort garantiert kollidieren. Gestapelte Branches wurden verworfen, weil
  jeder Merge einen Rebase durch den gesamten Stack erzwingt und `delivery.baseBranch` je PR von
  `origin/main` abweichen müsste. Die Reihenfolge A → B → C → D → E ist verbindlich: B liefert
  React 19.2.8 als Voraussetzung für D, und A wie C tragen die Sicherheitskorrekturen und stehen
  deshalb vorn.
- **Commit-Präfix `chore(deps):`, nicht `fix(deps):`.** `release-please-config.json` führt
  `packages/paratix` und `packages/create-paratix` als `release-type: node` mit `linked-versions`.
  Ein `fix(deps):`-Commit in einem der Pakete löst einen ungewollten Patch-Release beider Pakete aus.
  Die bestehende Historie (`dfe49a2a`, `9c7f0aff`) verwendet bereits `chore(deps):`.
- **`types: ["node"]` wird zentral in `tsconfig.json` gesetzt**, nicht je Paket. Beide Paket-Configs
  erben von dort; `tsconfig.root.json` und `scripts/tsconfig.json` überschreiben den Wert bereits
  selbst, `website/tsconfig.json` ist eigenständig.
- **Die Teilung von Batch C wird gemessen, nicht geschätzt.** `pnpm lint` läuft dort vor jeder
  Korrektur, und die Schwelle ist objektiv: reichen die bestehenden Override-Blöcke, bleibt der
  Batch zusammen; muss Produktcode in `packages/*/src` angefasst werden, wird der Toolchain-Bump
  von den Codekorrekturen getrennt. So hängt die Entscheidung an einem Messwert statt an einer
  Vorabschätzung der Befundmenge, die aus dem Changelog nicht ableitbar ist.
- **Alle fünf React-Router-v8-Future-Flags werden direkt gesetzt.** Der offizielle Upgrade-Guide
  empfiehlt, sämtliche Opt-ins zu übernehmen; für diese Website sind die vier nicht erzwungenen
  Flags einzeln als folgenlos nachgewiesen. Das nimmt die Unsicherheit aus Batch D heraus, statt
  sie auf eine mögliche Korrekturrunde nach dem ersten Build zu verschieben.

## Betroffene Dateien

| Datei                                                         | Beschreibung                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `package.json`                                                | `packageManager` auf `pnpm@11.17.0`; devDependencies `@types/node`, `concurrently`, `eslint`, `eslint-config-setup`, `oxlint`, `prettier`; `typescript` als npm-Alias auf `@typescript/typescript6`, neuer Eintrag `@typescript/native` als Alias auf `typescript@7` |
| `packages/paratix/package.json`                               | `@types/node`, `@vitest/coverage-v8`, `vitest`, `tsx`, `typescript`-Alias                                                                                                                                                                                            |
| `packages/create-paratix/package.json`                        | `@types/node`, `vitest`, `typescript`-Alias                                                                                                                                                                                                                          |
| `website/package.json`                                        | `react`, `react-dom`, `isbot`, `lucide-react`, `vite`, `react-router`, `@react-router/{dev,node,serve}`                                                                                                                                                              |
| `pnpm-lock.yaml`                                              | Auflösungsergebnis aller Batches                                                                                                                                                                                                                                     |
| `tsconfig.json`                                               | `ignoreDeprecations` entfernen, `types: ["node"]` ergänzen                                                                                                                                                                                                           |
| `website/app/routes/home.tsx`                                 | Vier Icon-Bezeichner in Import und JSX ersetzen (16 Vorkommen)                                                                                                                                                                                                       |
| `website/react-router.config.ts`                              | `future`-Block mit allen fünf v8-Flags                                                                                                                                                                                                                               |
| `eslint.config.ts`                                            | Nur falls `eslint-config-setup@0.5` neue Regeln meldet, die im Website-Override abzuschalten sind                                                                                                                                                                    |
| `oxlint.config.ts`                                            | Nur falls sich die Override-Struktur von `getOxlintConfig` mit oxlint 1.76 ändert                                                                                                                                                                                    |
| `pnpm-workspace.yaml`                                         | Nur falls Rolldown/Oxc neue Build-Freigaben unter `allowBuilds` benötigen                                                                                                                                                                                            |
| `AGENTS.md`                                                   | Optional (Batch E, Schritt 8): Hinweis auf den abweichenden Editor-Compiler im Side-by-side-Betrieb                                                                                                                                                                  |
| `docs/plan/2026-07-28-dependency-update-pending-approvals.md` | Dieser Plan; Statusmarker nach Abschluss                                                                                                                                                                                                                             |

Nicht betroffen: `.github/workflows/*` (Node 24 erfüllt alle neuen Engine-Anforderungen,
`pnpm/action-setup` liest die Version aus `packageManager`), `renovate.json`,
`packages/paratix/tsup.config.ts`, `website/vite.config.ts`.

## Implementierungsdetails

### Vorgehen

**Batch A — pnpm-Toolchain**

1. `packageManager` in `package.json` auf `pnpm@11.17.0` setzen und mit dieser Version neu
   installieren, damit das Lockfile-Format konsistent geschrieben wird.
2. Prüfen, ob `pnpm install --frozen-lockfile` (der CI-Aufruf) gegen das neu geschriebene Lockfile
   grün bleibt.
3. Isoliert halten: eine pnpm-Minor-Serie kann das Lockfile umfangreich umschreiben; vermischt mit
   Versionsänderungen wäre der Diff nicht mehr lesbar.

**Batch B — risikoarme Laufzeit- und Test-Updates**

1. `@types/node` auf `24.13.3` in allen drei Manifesten gleichzeitig (die Pins sind exakt, ein
   Auseinanderlaufen erzeugt doppelte Typbäume).
2. `concurrently` 10.0.4, `tsx` 4.23.1, `isbot` 5.2.1.
3. `vitest` und `@vitest/coverage-v8` gemeinsam auf 4.1.10 — `@vitest/coverage-v8` ist exakt gepinnt
   und muss zur `vitest`-Version passen.
4. `react` und `react-dom` gemeinsam auf `19.2.8`. Das ist die Voraussetzung für Batch D.

**Batch C — Lint- und Format-Toolchain**

1. `eslint` 10.8.0 und `eslint-config-setup` `^0.5.2` gemeinsam anheben (der neue Peer verlangt
   `eslint >= 10`).
2. `oxlint` auf `^1.76.0` anheben und dabei prüfen, dass die Version zum `eslint-plugin-oxlint` aus
   `eslint-config-setup` passt, damit Regeln nicht doppelt gemeldet werden.
3. **Messpunkt vor jeder Korrektur:** `pnpm lint` ausführen und die Befunde nur erfassen, noch
   nichts beheben. Die Teilungsschwelle ist objektiv und wird an diesem Ergebnis entschieden:
   - Lassen sich alle Befunde über die bestehenden Override-Blöcke in `eslint.config.ts`
     (`website/app/**/*.tsx`, `**/test/**`) auflösen, bleibt Batch C zusammen.
   - Sobald darüber hinaus Produktcode in `packages/*/src` geändert werden muss, wird Batch C
     geteilt: zuerst `eslint` und `oxlint` als eigener Durchgang, danach `eslint-config-setup` mit
     den zugehörigen Codekorrekturen. Der Toolchain-Bump bleibt so von inhaltlichen Änderungen
     getrennt und bleibt einzeln zurücknehmbar.
4. Befunde beheben. Echte Fehler im Produktcode werden korrigiert; nur wo eine Regel für eine
   bewusste Design-Entscheidung falsch anschlägt, wird der passende Override-Block erweitert — mit
   begründendem Kommentar im Stil der vorhandenen Blöcke.
5. `oxlint.config.ts` verifizieren: die Datei mutiert den bestehenden Test-Override von
   `getOxlintConfig` in place, weil oxlint `overrides` nach erstem Glob-Treffer auflöst. Ändert sich
   die von `eslint-config-setup` gelieferte Override-Struktur, muss diese Stelle nachgezogen werden.
6. **Separater Commit:** `prettier` auf 3.9.6 anheben, danach `pnpm format` über das ganze
   Repository laufen lassen und den Reformat-Diff eigenständig committen.

**Batch D — Website: React Router 8, Vite 8, lucide 1**

1. `lucide-react` auf `^1.27.0` und die vier Bezeichner in `website/app/routes/home.tsx` ersetzen
   (Import-Block und alle JSX-Verwendungen, 16 Vorkommen).
2. `vite` in `website/package.json` auf `^8.1.5`. `website/vite.config.ts` bleibt unverändert.
3. `react-router` sowie `@react-router/dev`, `@react-router/node`, `@react-router/serve` gemeinsam
   auf `8.3.0`.
4. In `website/react-router.config.ts` neben `prerender` und `ssr` einen `future`-Block mit allen
   fünf v8-Flags ergänzen: `v8_viteEnvironmentApi` (für Framework Mode verpflichtend) sowie
   `v8_middleware`, `v8_splitRouteModules`, `v8_passThroughRequests` und
   `v8_trailingSlashAwareDataRequests`. Die vier letzteren sind für diese Website als folgenlos
   nachgewiesen (siehe „Belegte Breaking Changes“); sie vorab zu setzen entspricht der offiziellen
   Migrationsempfehlung und schließt eine Korrekturrunde mitten im Batch aus.
5. Nach dem Build prüfen, ob Rolldown neue Build-Skript-Freigaben braucht; gegebenenfalls
   `allowBuilds` in `pnpm-workspace.yaml` ergänzen und den bestehenden Eintrag `esbuild: true`
   überprüfen, da esbuild unter Vite 8 nur noch optional ist.

**Batch E — TypeScript 7 im Side-by-side-Betrieb**

1. Vorarbeit in `tsconfig.json`: `"ignoreDeprecations": "6.0"` entfernen. Verifiziert: beide Pakete
   kompilieren mit TypeScript 6.0.3 ohne dieses Flag fehlerfrei, die Unterdrückung aus `bd7a4911`
   ist gegenstandslos geworden.
2. Vorarbeit in `tsconfig.json`: `"types": ["node"]` ergänzen, damit der neue TypeScript-7-Default
   `types: []` die Node-Globals nicht entzieht.
3. Beide Vorarbeiten noch unter TypeScript 6 mit `pnpm typecheck` absichern, bevor der Compiler
   gewechselt wird — so bleibt die Fehlerursache eindeutig.
4. Alias-Setup in allen vier Manifesten, die `typescript` führen: den Eintrag `typescript` auf
   `npm:@typescript/typescript6@^6.0.2` umstellen und **nur im Root** zusätzlich
   `"@typescript/native": "npm:typescript@^7.0.2"` aufnehmen. Damit liefert `tsc` in den Skripten den
   7.0-Compiler, während typescript-eslint und tsup weiterhin die 6.0-API über den Paketnamen
   `typescript` auflösen.
5. Der Root-Eintrag genügt für `typecheck:packages`, obwohl dieses Skript mit
   `pnpm -r --filter './packages/*' exec tsc` im Paketverzeichnis läuft: pnpm nimmt das
   `.bin`-Verzeichnis des Workspace-Roots in den PATH auf. Verifiziert am Bestand mit dem
   ausschließlich im Root installierten `oxlint`, das über `pnpm -r exec` in beiden Paketen
   auflöst. Nach dem Alias-Setup ist zu bestätigen, dass `@typescript/typescript6` im Paket nur
   `tsc6` bereitstellt und damit kein lokales `tsc` mehr den Root-Eintrag verdeckt.
6. Prüfen, dass der Peer `typescript: ">=4.8.4 <6.1.0"` von typescript-eslint gegen die aliasierte
   Version 6.0.2 erfüllt ist und `pnpm install` keine Peer-Warnung ausgibt.
7. `pnpm typecheck` über alle vier Konfigurationen laufen lassen: `tsconfig.root.json`, beide
   Paket-Configs samt `tsconfig.typecheck.json`, und `website` mit vorgelagertem
   `react-router typegen`.
8. In `AGENTS.md` beziehungsweise der Entwickler-Dokumentation vermerken, dass der Editor ohne die
   TypeScript-7-Erweiterung weiterhin den 6.0-Language-Server nutzt und damit von den Konsolenwerten
   abweichende Laufzeiten zeigt. Diese Dokumentationsergänzung ist optional und blockiert den Batch
   nicht.

### Randfälle

- **Prettier reformatiert Plan-Dokumente.** Die 133 Markdown-Dateien enthalten ~100 abgeschlossene
  Pläne unter `docs/plan/`. Erwartetes Verhalten: der Reformat-Commit fasst diese Änderungen
  gesammelt und ohne inhaltliche Anpassung; die Statusmarker der Pläne dürfen dabei nicht verändert
  werden.
- **`@vitest/coverage-v8` läuft aus dem Coverage-Gate.** `packages/paratix/vitest.config.ts` setzt
  Schwellen (statements/lines 90, functions 90, branches 82) knapp unter der gemessenen Basis. Ändert
  ein Coverage-Provider-Update die Messung, schlägt `pnpm test` fehl. Erwartetes Verhalten bei
  4.1.10: unverändert; andernfalls ist die Ursache zu klären, nicht die Schwelle zu senken.
- **Rolldown ändert das Bundling-Ergebnis der Website.** Der Prerender-Test
  `website/test/prerender.test.mjs` prüft das Build-Ergebnis. Erwartetes Verhalten: unverändert
  grüner Test; ein Fehlschlag deutet auf die geänderte CommonJS-`default`-Interop hin. Reaktion in
  dieser Reihenfolge: Vite 8 aus Batch D herauslösen und den Rest (React Router 8, lucide 1)
  eigenständig fertigstellen. Das von Vite als Übergang angebotene
  `legacy.inconsistentCjsInterop: true` ist nur zulässig, wenn es zusammen mit einem konkreten
  Folgeeintrag unter „Offene Punkte“ gesetzt wird — es ist als deprecated markiert und würde sonst
  dauerhaft im Repository stehen bleiben.
- **`paratix` selbst wird nicht von Vite gebaut.** Die Pakete nutzen `tsup` (esbuild-basiert). Vite 8
  betrifft ausschließlich `website` und die Vitest-Kette; die veröffentlichten Artefakte in
  `packages/*/dist` ändern sich durch Batch D nicht.
- **`agent:check` deckt den Integrationspfad nicht ab.** `pnpm test:integration` läuft nur über
  `agent:check:integration` und benötigt einen SSH-Zielhost. Nach Batch B und E ist mindestens ein
  Lauf sinnvoll, da `ssh2`-nahe Typen und Node-Globals betroffen sind.
- **Zwei Compiler im Baum erhöhen die Installationsgröße.** Erwartetes Verhalten: hinnehmbar, da
  beide reine devDependencies sind und nicht in die veröffentlichten Tarballs gelangen
  (`files: ["dist", "llm-guide.md"]`).

## Akzeptanzkriterien

- [ ] `pnpm agent:check` läuft nach jedem einzelnen Batch fehlerfrei durch (Lint, Format-Check,
      Typecheck, Build, Tests).
- [ ] `pnpm install --frozen-lockfile` ist gegen das committete `pnpm-lock.yaml` erfolgreich und
      gibt keine Peer-Dependency-Warnung aus.
- [ ] Alle 17 Einträge aus dem Abschnitt „Pending Approval“ von Issue #58 sind auf die in der
      Bestandsaufnahme genannten Zielversionen gehoben, nachgewiesen über die vier `package.json`
      und `pnpm ls -r`. Nicht geeignet als Nachweis ist `pnpm outdated -r`: `@types/node` bleibt
      bewusst auf der 24er-Linie, obwohl 26.1.2 veröffentlicht ist, und würde dort dauerhaft als
      veraltet erscheinen.
- [ ] `website/app/routes/home.tsx` enthält keinen der Bezeichner `Code2`, `Layers3`,
      `CheckCircle2`, `TerminalSquare` mehr, und `pnpm --filter @sebastian-gmbh/paratix-website build`
      ist erfolgreich.
- [ ] `pnpm --filter @sebastian-gmbh/paratix-website test` (Prerender-Test) ist grün.
- [ ] `website/react-router.config.ts` setzt alle fünf v8-Future-Flags, und der Build erzeugt zu
      keinem davon eine Warnung.
- [ ] In Batch C ist das Ergebnis des Messlaufs `pnpm lint` festgehalten und die daraus folgende
      Teilungsentscheidung im PR benannt.
- [ ] `tsconfig.json` enthält kein `ignoreDeprecations` mehr und setzt `types: ["node"]`.
- [ ] `npx tsc --version` meldet Version 7.x, während `pnpm ls typescript` die aliasierte
      Version 6.0.2 zeigt.
- [ ] Die Coverage-Schwellen in `packages/paratix/vitest.config.ts` sind unverändert und werden
      weiterhin erreicht.
- [ ] Kein Commit trägt das Präfix `fix(deps)` oder `feat(deps)` in einem der beiden
      release-please-verwalteten Pakete.
- [ ] Zu keinem Zeitpunkt ist mehr als ein Batch-PR gleichzeitig offen; jeder Branch ist von einem
      `origin/main` abgezweigt, das den Vorgänger-Batch bereits enthält.
- [ ] `pnpm audit` meldet nach dem letzten Batch keine Advisory, die vor Batch A nicht schon
      bestand.

## Validierungsplan

- Nach jedem Batch: `pnpm agent:check`.
- Nach Batch A: zusätzlich `pnpm install --frozen-lockfile` mit gelöschtem `node_modules`, um das neu
  geschriebene Lockfile gegen den CI-Pfad zu prüfen.
- Nach Batch C: `pnpm lint` und `pnpm format:check` getrennt betrachten; der Reformat-Commit muss
  `format:check` allein grün stellen.
- Nach Batch D: `pnpm --filter @sebastian-gmbh/paratix-website build` und der Prerender-Test, dazu
  eine manuelle Sichtprüfung der vier ersetzten Icons im gerenderten Ergebnis.
- Nach Batch E: `pnpm typecheck` über alle vier Konfigurationspfade, `pnpm build` für die
  `dts`-Erzeugung beider Pakete, sowie `pnpm ls typescript @typescript/native` zur Bestätigung der
  Alias-Auflösung.
- Nach Batch B und Batch E: `pnpm agent:check:integration`, sofern ein SSH-Zielhost verfügbar ist.
- Nach Batch A und nach Abschluss aller Batches: `pnpm audit`, um zu belegen, dass die als
  Sicherheitskorrektur eingestuften Updates (pnpm, `eslint-config-setup` 0.5.2, `vitest` 4.1.10)
  auch im aufgelösten Abhängigkeitsbaum ankommen und keine neuen Advisories eingeschleppt wurden.
- Abschließend über alle Batches hinweg: ein vollständiger CI-Lauf auf dem Zielbranch.

## Annahmen und offene Punkte

- **Annahme:** Die Renovate-Zielversionen aus Issue #58 sind zum Umsetzungszeitpunkt noch aktuell.
  Zwischen Planung und Umsetzung erschienene neuere Patches (etwa `oxlint` 1.76.0 gegenüber dem im
  Issue genannten 1.75.0) werden mitgenommen, solange sie keinen weiteren Major-Sprung darstellen.
- **Annahme:** Die Angaben zu Breaking Changes stammen aus den offiziellen Migrationsleitfäden und
  Changelogs; die Icon-Renames und der Peer-Bereich von typescript-eslint sind zusätzlich direkt
  gegen die publizierten Paketartefakte verifiziert.
- **Annahme:** `@types/node` bleibt bewusst auf der 24er-Linie, passend zu `engines.node >=24.0.0`.
  Renovate schlägt deshalb nur 24.13.3 vor, obwohl 26.1.2 veröffentlicht ist.
- **Annahme:** Die Dokumentationsergänzung zum abweichenden Editor-Compiler (Batch E, Schritt 8)
  ist bewusst optional und blockiert keinen Batch; sie kann in einen eigenen
  `/effective-flow docs`-Lauf ausgelagert werden.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       2 |       2 |
| Sicherheit  |        0 |       0 |       2 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       2 |
| Testbarkeit |        0 |       1 |       0 |
| Scope       |        0 |       1 |       1 |
| Wartbarkeit |        0 |       1 |       2 |

Der interaktive Plan-Review vom 2026-07-28 hat die Befunde unten ergänzt. Eine zweite Runde am
selben Tag hat die beiden verbliebenen offenen Punkte entschieden; der Plan enthält jetzt keine
offenen Punkte mehr und ist damit implementierbar.

### Befunde

- **Scope, wichtig (zweite Runde):** Der Umfang von Batch C stand als offener Punkt im Plan und
  blockierte die Klärungs-Prüfung vor der Implementierung. Aus dem Changelog ist die Befundmenge
  von `eslint-config-setup@0.5` nicht ableitbar — eine Vorabschätzung wäre geraten gewesen.
  Entschieden und eingearbeitet: `pnpm lint` läuft in Batch C vor jeder Korrektur, und die
  Teilungsschwelle hängt an diesem Messwert (Override-Blöcke reichen → zusammen; Produktcode in
  `packages/*/src` betroffen → Toolchain-Bump und Codekorrekturen trennen).
- **Architektur, wichtig (zweite Runde):** Die restlichen vier v8-Future-Flags waren als „zeigt
  erst der Build“ offengelassen. Prüfung gegen den Website-Code hat sie einzeln als folgenlos
  belegt — kein Custom Server, keine Loader, keine eigene `.data`-Logik, Prerender nur `/`.
  Entschieden und eingearbeitet: alle fünf Flags werden direkt gesetzt, passend zur offiziellen
  Migrationsempfehlung. Die Belege stehen als Tabelle unter „Belegte Breaking Changes“.
- **Architektur, wichtig:** Alle fünf Batches schreiben `pnpm-lock.yaml`. Bei `delivery.completion
= pr` und `delivery.baseBranch = origin/main` hätten gleichzeitig offene Batch-PRs sich
  garantiert gegenseitig blockiert — der Plan hatte die Staffelung beschrieben, aber die
  Auslieferungsform offengelassen. Entschieden und eingearbeitet: strikt sequenziell, ein PR pro
  Batch, jeweils erst nach dem Merge des Vorgängers. Als Architekturentscheidung und als
  Akzeptanzkriterium verankert.
- **Wartbarkeit, wichtig:** Das Akzeptanzkriterium hatte `pnpm outdated -r` als Nachweis
  vorgesehen. Das ist nicht erfüllbar: `@types/node` bleibt passend zu `engines.node >=24.0.0`
  bewusst auf der 24er-Linie, während 26.1.2 veröffentlicht ist, und würde dort dauerhaft als
  veraltet erscheinen. Der Nachweis läuft jetzt über die vier `package.json` und `pnpm ls -r`; die
  bewusste Deckelung ist als Annahme dokumentiert.
- **Testbarkeit, wichtig:** `pnpm agent:check` deckt den SSH-Integrationspfad nicht ab, obwohl
  Batch B (`@types/node`) und Batch E (Compilerwechsel, `types`-Default) genau die Node-Globals und
  `ssh2`-nahen Typen berühren, die dort zusammenlaufen. Eingearbeitet: der Validierungsplan fordert
  nach diesen beiden Batches zusätzlich `pnpm agent:check:integration`, und die Randfälle benennen
  die Lücke ausdrücklich.
- **Architektur, Hinweis:** Der Side-by-side-Betrieb zweier Compiler ist bewusst ein Zwischenzustand.
  Sobald typescript-eslint die TypeScript-7.1-API unterstützt, sollte der Alias auf
  `@typescript/typescript6` wieder entfernt werden. Der Plan hält dies als Architekturentscheidung
  mit Begründung fest, statt es implizit zu lassen.
- **Sicherheit, Hinweis:** Drei der Updates enthalten Sicherheitskorrekturen, die für sich genommen
  bereits ein Update rechtfertigen: pnpm 11.x (Path-Traversal beim Linking, `adm-zip`,
  Speicherbegrenzung im Auth-Token-Poll), `eslint-config-setup` 0.5.2 (gepinnte esbuild-Version) und
  `vitest` 4.1.10 (Dateisystemzugriff in Browser-Builtins). Batch A und Batch C sollten deshalb nicht
  hinter Batch D oder E zurückgestellt werden.
- **Fehlerfälle, Hinweis:** Die Coverage-Schwellen liegen dicht an der gemessenen Basis. Der Plan
  legt ausdrücklich fest, dass eine Schwellenabsenkung keine zulässige Reaktion auf einen
  Fehlschlag ist.
- **Scope, Hinweis:** Der Zwischenschritt `lucide-react@^0.577.0` aus dem Dashboard wird bewusst
  übersprungen, weil er dieselben vier Icon-Renames verlangt wie der Major. Das reduziert den Scope,
  ohne ein Update auszulassen — die Zielversion liegt über beiden Dashboard-Einträgen.
- **Wartbarkeit, Hinweis:** Die Commit-Präfix-Regel (`chore(deps):` statt `fix(deps):`) ist keine
  Stilfrage, sondern verhindert einen ungewollten Release beider veröffentlichter Pakete über
  release-please. Sie ist als Architekturentscheidung und als Akzeptanzkriterium verankert.
- **Wartbarkeit, Hinweis:** Batch E, Schritt 8 sah eine Ergänzung in `AGENTS.md` vor, die Datei
  fehlte aber in „Betroffene Dateien“ und stand implizit unter „Nicht betroffen“. Eingearbeitet:
  `AGENTS.md` ist jetzt als optional betroffene Datei geführt.
- **Fehlerfälle, Hinweis:** Für einen Interop-Fehlschlag unter Rolldown fehlte die Reaktion.
  Eingearbeitet: primär wird Vite 8 aus Batch D herausgelöst; das von Vite angebotene
  `legacy.inconsistentCjsInterop` ist deprecated und nur zusammen mit einem Folgeeintrag unter
  „Offene Punkte“ zulässig.
- **Sicherheit, Hinweis:** Der Plan stufte drei Updates als Sicherheitskorrektur ein, prüfte das
  Ergebnis im aufgelösten Abhängigkeitsbaum aber nicht nach. Eingearbeitet: `pnpm audit` nach
  Batch A und nach dem letzten Batch, mit passendem Akzeptanzkriterium.
- **Architektur, Hinweis (geprüft, kein Handlungsbedarf):** Das Alias-Setup hätte `tsc` in
  `typecheck:packages` unauffindbar machen können, weil dieses Skript über
  `pnpm -r --filter './packages/*' exec` im Paketverzeichnis läuft und `@typescript/typescript6`
  dort nur `tsc6` bereitstellt. Am Bestand verifiziert: pnpm nimmt das `.bin` des Workspace-Roots
  in den PATH auf — das ausschließlich im Root installierte `oxlint` löst über `pnpm -r exec` in
  beiden Paketen auf. `@typescript/native` bleibt deshalb ein reiner Root-Eintrag; die
  Bestätigung ist als Schritt 5 in Batch E verankert.

## Offene Punkte

- Keine offenen Punkte.

## Nachtrag zur Umsetzung

Umgesetzt in fünf Pull Requests: #168 (pnpm), #169 (Laufzeit- und Test-Patches),
#170 (Lint und Format), #171 (Website), #172 (TypeScript 7).

Fünf Annahmen dieses Plans haben sich dabei als falsch erwiesen. Sie stehen hier,
damit spätere Leser ihnen nicht aufsitzen.

- **`ignoreDeprecations: "6.0"` war nicht überflüssig.** Die Verifikation in der
  Planungsphase rief `tsc` gegen die Paket-Configs auf und verfehlte damit den
  dts-Pfad, den der ursprüngliche Commit im Namen trug. `tsup` setzt dort hart
  `baseUrl`. Die Unterdrückung liegt jetzt in den beiden tsup-Configs.
- **TypeScript 7 lehnt `ignoreDeprecations` nicht ab.** 7.0.2 akzeptiert die
  Option klaglos. Die gegenteilige Behauptung unter „Belegte Breaking Changes"
  trifft auf den Sprachdienst zu, nicht auf den CLI-Compiler.
- **Die React-Router-Future-Flags gehören nicht nach v8.** Der Upgrade-Guide
  beschreibt die Vorbereitung, während man noch auf v7 ist. Auf v8 lehnt der
  Build alle fünf ab, weil die Verhalten dort Standard sind. Die korrekte
  Konfiguration ist kein `future`-Block. Die Entscheidung aus dem Plan-Review,
  alle fünf zu setzen, war damit gegenstandslos.
- **Der Prettier-Reformat traf TypeScript, nicht Markdown.** Erwartet wurden 133
  Markdown-Dateien wegen des micromark-Wechsels. Tatsächlich waren es 25 Dateien,
  davon 23 TypeScript, weil 3.9 mehrzeilige Union-Typaliase zusammenzieht.
- **Die Teilungsregel für Batch C griff ins Leere.** Sie unterstellte, der
  Befundberg komme aus `eslint-config-setup` 0.5. Gemessen kamen 27 von 28
  Befunden aus der transitiven Plugin-Auffrischung, vor allem typescript-eslint
  8.59.1 auf 8.65.0.

Nicht im Plan vermerkt war außerdem, dass `pnpm update` in pnpm 11 die Range in
der `package.json` auf die neu aufgelöste Version anhebt. Die Batches B und C
haben deshalb mehr Manifest-Zeilen verändert, als ihre Beschreibungen
ankündigten.

Das Alias auf `typescript` ist ein bewusster Zwischenzustand. Sobald
typescript-eslint und tsup die TypeScript-7.1-API unterstützen, fallen beide
Einträge wieder zu einer einzelnen `typescript`-Abhängigkeit zusammen.
