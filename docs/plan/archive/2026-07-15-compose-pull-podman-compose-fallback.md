# compose.pull: Graceful Fallback für podman-compose ohne `config --format json`

**Planungsstatus:** Umgesetzt
**Quelle:** /firmo plan
**Empfohlener Workflow:** Bugfix (`/firmo fix`)

## Anforderung

`compose.pull({ runtime: "podman" })` bricht auf jedem Host ab, dessen `podman compose`
über den Python-Provider **`podman-compose`** (statt Compose v2) läuft. Ursache ist der seit
0.14.0 (#120) vorgeschaltete Image-Enumerationsschritt für die digest-basierte
Change-Detection:

```
cd <projectDirectory> && podman compose config --format json
```

`podman-compose` (getestet 1.0.6) kennt `--format json` nicht; sein `argparse` beendet mit
**exit code 2**. paratix meldet das als `[compose.pull] failed to resolve images` und die
einzige stderr-Zeile ist der podman-compose-Startbanner — die eigentliche Ursache bleibt
verborgen, und der gesamte Pull (und damit das Deployment) schlägt fehl.

Ziel: `compose.pull` mit `runtime: "podman"` funktioniert unabhängig davon, ob der
Compose-Provider Compose v2 oder das Python-`podman-compose` ist. Die digest-basierte
Change-Detection ist ein Nice-to-have; ein fehlgeschlagener Pull darf das Deployment nicht
blockieren.

Dies ist – nach dem `--project-directory`-Flag (Issue #60) – bereits die dritte
Inkompatibilität zwischen paratix' podman-compose-Pfad und dem Python-Provider. Der Fix folgt
demselben Muster: den Provider-Unterschied tolerieren, statt eine harte Anforderung zu setzen.

**Gewählter Ansatz:** Option 1 aus dem Issue (Graceful Fallback). Schlägt die
Image-Enumeration fehl oder ist ihr Output unbrauchbar, wird die Change-Detection
übersprungen und ein einfacher `<runtime> compose pull` ausgeführt. Der Status wird in diesem
Fallback konservativ als **`changed`** gemeldet (Entscheidung, siehe unten).

## Architekturentscheidungen

- **Option 1 (Graceful Fallback) statt Option 2/3.** Option 2 (Provider-kompatible
  Enumeration ohne `--format json`) würde einen zweiten, fragilen Parser-Pfad einführen;
  Option 3 (Compose v2 verpflichtend, klarer Fehler) verschlechtert eine bislang
  funktionierende Nutzung. Option 1 ist am wenigsten überraschend und deckt zugleich weitere
  Fehlerursachen der Enumeration ab (z. B. übergroßer Config-Output).
- **Generischer Fallback, keine Provider-Erkennung.** Der Fallback greift bei **jedem**
  Fehlschlag der Image-Enumeration (non-zero exit **oder** nicht parsbarer/übergroßer
  JSON-Output), nicht nur beim spezifischen podman-compose-Signal. Vorteil: kein fragiles
  Provider-Sniffing (`compose_providers` in `containers.conf`), und ein tatsächlich kaputtes
  Compose-Projekt scheitert weiterhin sichtbar – dann am nachfolgenden `compose pull` selbst,
  mit dessen eigener, aussagekräftiger Fehlermeldung.
- **Fallback-Status = `changed` (konservativ).** Ist die digest-basierte Detection nicht
  verfügbar, meldet der erfolgreiche Fallback-Pull `changed`. Begründung: `compose.pull` ist
  Signal-Style (`check` liefert immer `needs-apply`), und an `changed` gekoppelte
  nachgelagerte Handler (z. B. Restart/Notify) müssen zuverlässig feuern, wenn ein neues Image
  geladen wurde. Ein podman-compose-Pull-Output entspricht nicht dem Docker-Format, daher wäre
  eine Text-Heuristik (die pre-#120-Variante `composePullReportedChange`) auf genau diesen
  Hosts unzuverlässig und würde echte Updates fälschlich als `ok` verbergen. Der Preis –
  podman-compose-Hosts melden bei jedem Lauf `changed` (Rauschen) – ist bewusst akzeptiert,
  da ein zu viel ausgelöster Restart ungefährlicher ist als ein verpasstes Update.
- **Kontrakt von `resolveComposeConfigImages` ändern.** Die Funktion wird ausschließlich von
  `compose.pull` genutzt. Statt bei Fehlschlag ein `ModuleResult` (harten Fehler)
  zurückzugeben, signalisiert sie „Enumeration nicht verfügbar“ mit `null`. Der Pull-Apply
  entscheidet dann zwischen Digest-Pfad (Array) und Fallback-Pfad (`null`). Das spiegelt das
  bereits vorhandene, tolerante Verhalten der Schwester-Funktion `resolveComposeProjectName`
  (`compose.ts:396`), die bei non-zero exit `null` liefert.

## Betroffene Dateien

| Datei                                           | Beschreibung                                                                                                                                                                                                                                                                                 |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/compose.ts`       | `resolveComposeConfigImages` gibt bei Enumerationsfehler `null` statt `ModuleResult` zurück; `compose.pull.apply` verzweigt in Digest-Pfad (Array) oder Fallback-Pfad (`null` → einfacher `compose pull`, Status `changed`).                                                                 |
| `packages/paratix/test/modules/compose.test.ts` | Neue/angepasste Tests für den Fallback-Pfad; bestehender Test „returns failed when config resolution fails“ (`compose.test.ts:~479`, prüft `failed to resolve images`) wird auf das neue Fallback-Verhalten umgestellt.                                                                      |
| `packages/paratix/llm-guide.md`                 | Kurze Doku-Notiz direkt unter der `compose`-Methodentabelle (nach `compose.pull`, vor `### download`): Unter `runtime: "podman"` mit dem Python-`podman-compose`-Provider entfällt die digest-basierte Change-Detection; `compose.pull` meldet dort nach erfolgreichem Pull stets `changed`. |

## Implementierungsdetails

### Vorgehen

1. **`resolveComposeConfigImages` toleranter machen** (`compose.ts:262`): Rückgabetyp von
   `ModuleResult | string[]` auf `string[] | null` ändern.
   - Bei `result.code !== 0`: `null` zurückgeben (kein `failedCommand` mehr).
   - Bei nicht parsbarem/übergroßem Output (`parseComposeConfigImages` liefert `null`):
     ebenfalls `null` zurückgeben (kein `failed` mehr).
   - Bei Erfolg: das sortierte `string[]` wie bisher.
2. **`compose.pull.apply` anpassen** (`compose.ts:1584` ff.): Die Verzweigung so umbauen, dass
   ein `null`-Ergebnis der Enumeration den Digest-basierten Pfad überspringt.
   - **Digest-Pfad (Enumeration lieferte ein Array):** unverändert –
     `snapshotComposeImagesBeforePull` → `compose pull` → `snapshotComposeImagesAfterPull` →
     `composeImageSnapshotChanged` → `changed`/`ok`.
   - **Fallback-Pfad (Enumeration lieferte `null`):** direkt
     `<runtime> compose pull 2>&1` ausführen; bei `result.code !== 0` weiterhin
     `failedCommand("[compose.pull] failed for <projectDirectory>", result)` (die echte
     Fehlermeldung des Providers bleibt sichtbar); bei Erfolg `{ status: "changed" }`.
   - Der `compose pull`-Aufruf ist in beiden Pfaden identisch; die Umsetzung soll die
     bestehende Kommando-Konstruktion (`composeCommand(runtime, projectDirectory) + " pull 2>&1"`)
     wiederverwenden und nicht duplizieren, wo sinnvoll.
3. **Kein neues öffentliches API.** Signatur und Optionen von `compose.pull` bleiben
   unverändert; nur das interne Verhalten bei nicht verfügbarer Enumeration ändert sich.
4. **Doku-Notiz in `llm-guide.md`** (Scope-Entscheidung: „Fallback + Doku-Notiz“): Direkt
   unter der `compose`-Methodentabelle (nach `compose.pull`, vor `### download`) eine kurze
   Notiz ergänzen. Inhalt: `compose.pull` erkennt Image-Änderungen digest-basiert; steht der
   Compose-Provider dafür nicht bereit (Python-`podman-compose` unterstützt
   `config --format json` nicht), entfällt die Change-Detection und der Pull meldet nach
   Erfolg stets `changed`. Der Docker- und der Compose-v2-Pfad bleiben unberührt. Die Notiz
   bleibt knapp; keine Änderung an der Tabellenzeile bzw. am `Partial`-Marker.

**Scope-Abgrenzung:** Der Fix betrifft ausschließlich `compose.pull`. Die zweite Nutzung von
`config --format json` in `resolveComposeProjectName` (`compose.ts:396`, genutzt vom
Volumes-Check in `compose.down`) toleriert einen non-zero exit bereits (Rückgabe `null` →
`composeProjectVolumesExist` liefert konservativ `true`) und ist von diesem Bug **nicht**
betroffen. Sie wird nicht verändert.

### Edge Cases

- **podman-compose ohne `--format json` (Kernfall):** `config` → exit 2 → `null` → Fallback →
  `compose pull` gelingt → `changed`. Kein Abbruch mehr.
- **Genuin kaputtes Compose-Projekt** (fehlende/ungültige `compose.yml`): `config` schlägt
  fehl → Fallback → `compose pull` schlägt ebenfalls fehl → `failedCommand` mit der
  aussagekräftigen Provider-Fehlermeldung. Sichtbarkeit bleibt erhalten, nur die
  Fehlerquelle verschiebt sich vom Enumerations- zum Pull-Kommando.
- **Übergroßer Config-Output** (> `COMPOSE_CONFIG_JSON_MAX_BYTES`): `parseComposeConfigImages`
  liefert `null` → Fallback statt hartem Fehler.
- **Compose v2 (Docker oder podman mit Compose-v2-Plugin):** `config --format json` gelingt →
  Digest-Pfad unverändert → präzise `changed`/`ok`-Meldung wie bisher. Keine Regression.
- **Leere Service-Liste** (Config gelingt, keine `image:`-Felder): liefert `[]` (kein `null`)
  → Digest-Pfad mit leeren Snapshots → `pull` → `ok`. Verhalten unverändert.

## Akzeptanzkriterien

- [ ] `compose.pull({ runtime: "podman" })` schlägt **nicht** mehr fehl, wenn
      `config --format json` mit exit 2 endet; stattdessen wird `compose pull` ausgeführt und bei
      Erfolg `{ status: "changed" }` zurückgegeben. (Unit-Test)
- [ ] Wenn `config --format json` gelingt und valides JSON liefert, bleibt die digest-basierte
      `changed`/`ok`-Erkennung unverändert. (bestehende Tests grün)
- [ ] Wenn der Fallback-Pull selbst fehlschlägt (`code !== 0`), wird weiterhin ein
      `failedCommand` mit der Provider-stderr/-stdout zurückgegeben. (Unit-Test)
- [ ] Der bisherige harte Fehlerpfad „failed to resolve images“ existiert nicht mehr; der
      zugehörige Test ist auf das Fallback-Verhalten umgestellt.
- [ ] `packages/paratix/llm-guide.md` enthält unter der `compose`-Methodentabelle die
      Doku-Notiz zum podman-compose-Fallback (Change-Detection entfällt, Pull meldet `changed`).
- [ ] `pnpm agent:check` (Lint, Typecheck, Tests, Build) läuft grün durch.

## Validierungsplan

- `pnpm agent:check` gemäß `AGENTS.md` als Gesamt-Gate (Lint, Type-Check, Tests, Build).
- Gezielte Unit-Tests in `packages/paratix/test/modules/compose.test.ts` über den bestehenden
  `mockSsh`-Ansatz:
  - Provider ohne JSON-Support: `config --format json` → `{ code: 2, stderr: "podman-compose: error: unrecognized arguments: --format json" }`, `compose pull 2>&1` → `{ code: 0, stdout: "…" }` ⇒ Ergebnis `changed`, und die Snapshot-/`image inspect`-Kommandos werden nicht aufgerufen.
  - Fallback-Pull schlägt fehl: `config` → exit 2, `compose pull 2>&1` → `{ code: 1, stderr: "…" }` ⇒ `failed` mit weitergereichter Meldung.
  - Regressionsschutz: erfolgreicher `config`-Pfad meldet weiterhin korrekt `changed` bzw. `ok` über die Digest-Snapshots.

## Annahmen und offene Punkte

- Annahme: `resolveComposeConfigImages` hat außerhalb von `compose.pull` keine weiteren Aufrufer
  (per Grep bestätigt); die Kontraktänderung auf `string[] | null` ist damit lokal begrenzt.
- Annahme: Es ist akzeptabel, dass podman-compose-Hosts im Fallback bei jedem Lauf `changed`
  melden; nachgelagerte, an `changed` gekoppelte Handler feuern dort folglich bei jedem Lauf.
  (Bewusste Entscheidung, siehe Architekturentscheidungen.)
- Doku: Die `llm-guide.md`-Tabelle listet `compose.pull` als „Partial“; die Tabellenzeile
  bleibt unverändert. Ergänzt wird lediglich eine kurze Notiz unter der Tabelle
  (Scope-Entscheidung „Fallback + Doku-Notiz“), die das entfallende Change-Detection-Verhalten
  unter dem Python-`podman-compose`-Provider beschreibt.
- Scope-Entscheidung getroffen: minimaler Fallback **plus** Doku-Notiz. Eine zentrale
  Provider-Kompatibilitäts-Guard (breitere Anti-Regressions-Maßnahme) wurde bewusst nicht
  aufgenommen, um den Eingriff regressionsarm zu halten.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       1 |
| Testbarkeit |        0 |       0 |       0 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- Hinweis (Architektur/Wartbarkeit): Die Kontraktänderung von `resolveComposeConfigImages`
  (`ModuleResult | string[]` → `string[] | null`) ist sauber, weil die Funktion nur einen
  Aufrufer hat. Bei künftigen weiteren Aufrufern muss die `null`-Semantik („Enumeration nicht
  verfügbar“, nicht „Fehler“) klar dokumentiert bleiben – ein kurzer JSDoc-Hinweis an der
  Funktion wird empfohlen.
- Hinweis (Fehlerfälle): Der generische Fallback verschiebt die Fehlersichtbarkeit eines
  genuin kaputten Compose-Projekts vom `config`- auf das `pull`-Kommando. Das ist gewollt und
  in „Edge Cases“ dokumentiert; die Fehlermeldung bleibt aussagekräftig, da `pull` seine
  eigene stderr weiterreicht.
- Hinweis (Scope): Interaktiver Plan-Review geklärt – Scope auf „Fallback + Doku-Notiz“
  festgelegt (breitere Provider-Guard bewusst ausgeklammert). Zweite `config --format json`-
  Nutzung in `compose.down` ist bereits tolerant und bleibt unverändert.

## Offene Punkte

- Keine offenen Punkte.
