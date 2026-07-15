# quadlet.network-Modul für isolierte Multi-Container-Stacks

**Planungsstatus:** Umgesetzt
**Quelle:** /firmo plan
**Empfohlener Workflow:** Feature (`/firmo build`)

## Anforderung

GitHub-Issue [#143](https://github.com/sebastian-software/paratix/issues/143) fordert ein neues
Modul `quadlet.network`, das ein Podman-Netzwerk als Quadlet-`.network`-Unit deklariert – genau so,
wie `quadlet.container` einen `.container`-Unit deklariert. Heute gibt es keinen erstklassigen Weg,
einem Multi-Container-Quadlet-Stack ein isoliertes internes Netzwerk zu geben. Die beiden bisherigen
Behelfe (`--network=host` via `podmanArgs`, das jede Isolation aufgibt, oder eine handgeschriebene
`.network`-Datei via `file.copy`, die außerhalb des Quadlet-Modulsystems liegt) entfallen damit.

Vorgeschlagene API (aus dem Issue, wörtlich übernommen):

```
quadlet.network({
  name: string,            // Pflicht; Unit wird <name>.network
  internal?: boolean,      // keine externe Konnektivität
  subnet?: string,
  gateway?: string,
  ipRange?: string,
  driver?: string,         // z. B. "bridge"
  disableDns?: boolean,
  label?: Record<string, string>,
  options?: Record<string, string>,
  podmanArgs?: string[],
}): Module
```

Container referenzieren das Netzwerk über die bereits vorhandene `networks`-Option
(`networks: ["app.network"]`). Ein Begleit-Modul `quadlet.volume` ist laut Issue **nicht** nötig.

**Erweiterung über die Issue-API hinaus (im Review abgestimmt):** Zusätzlich zur Issue-API werden
die häufig benötigten Netzwerk-Felder `ipv6?: boolean`, `dns?: string[]` und `ipamDriver?: string`
aufgenommen (→ `IPv6=`, `DNS=`, `IPAMDriver=`). Diese sind additiv und decken Dual-Stack, statische
DNS-Server und die IPAM-Driver-Wahl ab, ohne den `podmanArgs`-Behelf zu erzwingen.

**Warum Feature (`/firmo build`):** Es entsteht neue, öffentlich sichtbare Funktionalität (eine neue
Modul-Methode inklusive TypeScript-Typ, Doku-Eintrag und Tests), kein Fehler wird behoben und kein
Verhalten wird umstrukturiert.

## Architekturentscheidungen

- **Maximale Wiederverwendung der vorhandenen Quadlet-Infrastruktur.** Das Schreiben, Prüfen,
  Symlink-Verweigern, atomare Schreiben und der `daemon-reload` sind in
  `quadletFileHelpers.ts` (`applyQuadletFile`, `checkQuadletFile`) bereits generisch über
  `content` und `filePath` parametrisiert. `quadlet.network` nutzt exakt dieselben Helfer; es
  entsteht **keine** parallele Datei-I/O-Logik. Damit erbt das Netzwerk-Modul dieselben
  Sicherheits- und Idempotenz-Garantien wie `quadlet.container`.
- **Unit-Struktur: `[Unit]`-Description + `[Network]` (Variante A, mit dem User abgestimmt).** Die
  generierte Datei enthält eine minimale `[Unit]`-Sektion mit `Description=` (Default
  `Podman network: <name>`, per `description`-Option überschreibbar) und den `[Network]`-Block.
  **Kein** `[Install]`-Block und **keine** `Wants=/After=network-online.target`-Zeilen: Podman legt
  das Netzwerk lazy an, sobald ein referenzierender Container startet; die generierte
  Container-Service hängt automatisch am Netzwerk-Unit. Die `network-online`- und `Install`-Zeilen
  aus `quadlet.container` haben für ein Netzwerk-Unit keine sinnvolle Entsprechung und würden einen
  unnötigen Boot-Start erzwingen bzw. eine semantisch falsche Ordering-Abhängigkeit setzen.
- **`NetworkName=<name>` wird explizit gesetzt.** Ohne diese Zeile würde Podman den tatsächlichen
  Netzwerknamen auf `systemd-<name>` ableiten. Das Issue nennt `NetworkName=` ausdrücklich in den
  erwarteten Keys; ein explizit gesetzter Name macht den realen Netzwerknamen vorhersagbar und
  deckungsgleich mit dem Unit-Namen.
- **Wert-Validierung: nur Steuerzeichen (mit dem User abgestimmt).** `name` wird über das vorhandene
  `validateQuadletName` geprüft (gleiche Regeln wie beim container-Modul: kein führendes `-`, kein
  reiner Punkt-Name, Unit-Namen-Muster). Alle übrigen Werte (`subnet`, `gateway`, `ipRange`,
  `driver`, `label`-/`options`-Werte, `podmanArgs`) laufen über den vorhandenen
  `renderQuadletLine`-Pfad, der bereits Steuerzeichen ablehnt. **Keine** semantische CIDR-/IP-Prüfung
  – das übernimmt Podman beim Apply, konsistent mit der Behandlung von `ip`/`ip6` in
  `quadlet.container`.
- **Erweiterte Feld-Menge (`ipv6`, `dns`, `ipamDriver`, im Review abgestimmt).** Über die Issue-API
  hinaus werden `IPv6=` (bool), `DNS=` (repeated) und `IPAMDriver=` unterstützt. Alle drei sind
  optional und rein additiv; sie ändern nichts am Verhalten, wenn sie nicht gesetzt werden. Keine
  semantische Prüfung der Werte (nur Steuerzeichen), konsistent mit der abgestimmten
  Validierungsstrategie.
- **Warn-Detail bei bereits existierendem Live-Netzwerk (im Review abgestimmt).** Podman legt ein
  Netzwerk genau einmal an; ein `daemon-reload` regeneriert nur die Unit, überträgt aber keine
  geänderten `subnet`/`gateway`/… auf ein bereits laufendes Netzwerk. Wenn `apply` (bzw. der Dry-Run)
  einen Content-Wechsel bewirkt **und** ein Netzwerk mit demselben `NetworkName` auf dem Host bereits
  existiert (`podman network exists -- <name>`), ergänzt das Modul einen Hinweis-Detail im
  `ModuleResult`, dass das laufende Netzwerk nicht automatisch neu angelegt wird. Der Status bleibt
  `changed`; die Prüfung ist read-only und non-fatal (fehlt `podman`, entfällt der Hinweis, `apply`
  schlägt nicht fehl).
- **Eigener Reload-Flag-Namespace `quadlet-network-`.** Der versionierte `daemon-reload`-Flag nutzt
  einen eigenen Präfix, damit Container- und Netzwerk-Units mit gleichem Namen sich nicht
  gegenseitig überschreiben.
- **Netzwerk-spezifisches Modul-Label in den Helfer-Fehlermeldungen.** `applyQuadletFile` /
  `checkQuadletFile` erzeugen Fehlermeldungen mit hartkodiertem Präfix `[quadlet.container: …]`. Für
  korrekte Diagnose bei Netzwerk-Fehlern wird ein optionaler `label`-Parameter eingeführt (Default
  `quadlet.container`, damit das container-Modul unverändert bleibt), den `quadlet.network` mit
  `quadlet.network` belegt.

## Betroffene Dateien

| Datei                                                | Beschreibung                                                                                                                                                                                                                                                       |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/paratix/src/modules/quadletHelpers.ts`     | Neuer Typ `QuadletNetworkOptions`; Funktionen `buildQuadletNetworkLines`, `generateNetworkQuadlet` (bzw. Rendering des `[Unit]`+`[Network]`-Unit-Texts) und `getQuadletNetworkFilePath`. Wiederverwendung der vorhandenen `renderQuadlet*`-Helfer.                 |
| `packages/paratix/src/modules/quadletFileHelpers.ts` | `applyQuadletFile`/`checkQuadletFile` um optionalen `label`-Parameter (Default `quadlet.container`) erweitern, damit Fehlermeldungen für Netzwerk-Units `quadlet.network` nennen. Verhalten für Bestandsaufrufe unverändert.                                       |
| `packages/paratix/src/modules/quadlet.ts`            | Neue Methode `network(options: QuadletNetworkOptions): Module` im `quadlet`-Objekt: Validierung, Content-Erzeugung, `quadlet-network-`-Reload-Flag, `apply`/`check`/`_applyDryRun` analog zu `container` plus Warn-Detail bei bereits existierendem Live-Netzwerk. |
| `packages/paratix/test/modules/quadlet.test.ts`      | Neue Testfälle für `quadlet.network` (siehe Validierungsplan).                                                                                                                                                                                                     |
| `packages/paratix/llm-guide.md`                      | Neue Zeile `quadlet.network` in der `quadlet`-Modultabelle (Abschnitt `### quadlet`) und im Dry-Run-Ausgabe-Abschnitt analog zu `quadlet.container`.                                                                                                               |

## Implementierungsdetails

### Vorgehen

1. In `quadletHelpers.ts` den exportierten Typ `QuadletNetworkOptions` anlegen: `name` Pflicht;
   optional `description`, `internal`, `subnet`, `gateway`, `ipRange`, `driver`, `disableDns`,
   `ipv6`, `ipamDriver`, `dns`, `label`, `options`, `podmanArgs`. Über die Issue-API hinaus:
   `description` (folgt aus Variante A der Unit-Struktur) sowie die im Review abgestimmten Felder
   `ipv6` (bool), `dns` (string[]) und `ipamDriver` (string).
2. `buildQuadletNetworkLines(options)` implementieren, das die `[Network]`-Zeilen in einer stabilen,
   deterministischen Reihenfolge erzeugt (siehe unten). Ausschließlich die vorhandenen Helfer
   `renderQuadletLine`, `maybeRenderQuadletLine`, `maybeRenderQuadletBool`, `renderQuadletKeyValue`
   und `renderQuadletRepeated` nutzen, damit Steuerzeichen-Prüfung, Sortierung und Kompaktierung
   identisch zum container-Pfad greifen.
3. `generateNetworkQuadlet(options)` implementieren: `renderQuadletSection("Unit", [Description])`
   gefolgt von `renderQuadletSection("Network", buildQuadletNetworkLines(options))`, mit `join("\n")`
   und `trimEnd()` wie bei `generateContainerQuadlet`. Description-Default:
   `Podman network: <name>`.
4. `getQuadletNetworkFilePath(name)` implementieren, das
   `/etc/containers/systemd/<name>.network` zurückgibt (analog `getQuadletContainerFilePath`, gleicher
   `CONTAINERS_SYSTEMD_DIRECTORY`-Konstantenwert).
5. In `quadletFileHelpers.ts` `applyQuadletFile`/`checkQuadletFile` um einen optionalen
   `label`-Parameter erweitern und die hartkodierten `[quadlet.container: …]`-Präfixe durch das Label
   ersetzen (Default bleibt `quadlet.container`). Bestehende Aufrufer bleiben unverändert.
6. In `quadlet.ts` die Methode `network(options)` ergänzen:
   - `validateQuadletName(options.name)`.
   - `content = generateNetworkQuadlet(options)`, `filePath = getQuadletNetworkFilePath(name)`.
   - Reload-Flag über eine `quadlet-network-`-Variante von `buildQuadletReloadFlag` (den Präfix
     parametrisieren oder eine parallele kleine Funktion einführen; identische Hash-Logik).
   - `apply`, `check`, `_applyDryRun`, `_dryRunDiffProducer` **strukturgleich** zu `container`,
     inklusive `setVersionedFlag`/`hasFlag` und der Dry-Run-Diff-Erzeugung (die vorhandene
     `buildQuadletContainerDryRunDiff` ist bereits generisch über `filePath`/`desired` und lässt sich
     wiederverwenden; ihr Name kann bleiben oder neutral umbenannt werden).
   - **Warn-Detail bei existierendem Live-Netzwerk:** Eine kleine, read-only Hilfsfunktion prüft per
     `podman network exists -- <shellQuote(name)>` (`ignoreExitCode`, `silent`), ob das Netzwerk auf
     dem Host bereits existiert. Im `changed`-Zweig von `apply` (Content geändert) **und** bei
     existierendem Netzwerk wird das `ModuleResult.detail` um einen Hinweis ergänzt, dass das laufende
     Netzwerk nicht neu angelegt wird (manuelles Entfernen nötig, um subnet/gateway-Änderungen zu
     übernehmen). Fehlt `podman` oder ist die Prüfung nicht auswertbar (Exit ≠ 0), entfällt der
     Hinweis; `apply` bleibt erfolgreich. Dieselbe Probe ergänzt im `_applyDryRun` den Hinweis, da
     sie read-only ist.
   - `name: quadlet.network: <name>`.
7. `llm-guide.md` um die `quadlet.network`-Zeile in der Modultabelle und im
   Dry-Run-Ausgabe-Abschnitt ergänzen (Signatur aus `QuadletNetworkOptions`, `Yes` bei Dry-Run wie
   `quadlet.container`).

### Reihenfolge der `[Network]`-Zeilen (deterministisch)

1. `NetworkName=<name>`
2. `Driver=<driver>` (nur wenn gesetzt)
3. `IPAMDriver=<ipamDriver>` (nur wenn gesetzt)
4. `Internal=true|false` (nur wenn gesetzt)
5. `IPv6=true|false` (nur wenn gesetzt)
6. `DisableDNS=true|false` (nur wenn gesetzt)
7. `Subnet=<subnet>` (nur wenn gesetzt)
8. `Gateway=<gateway>` (nur wenn gesetzt)
9. `IPRange=<ipRange>` (nur wenn gesetzt)
10. `DNS=<server>` je Eintrag in Eingabereihenfolge (`renderQuadletRepeated`)
11. `Options=<k>=<v>` je Eintrag als **wiederholte Zeile**, alphabetisch nach Schlüssel sortiert (`renderQuadletKeyValue`)
12. `Label=<k>=<v>` je Eintrag als **wiederholte Zeile**, alphabetisch nach Schlüssel sortiert (`renderQuadletKeyValue`)
13. `PodmanArgs=<arg>` je Eintrag in Eingabereihenfolge (`renderQuadletRepeated`)

`Options=` und `Label=` werden als wiederholte `key=value`-Zeilen gerendert (je eine pro Eintrag),
nicht als kommaseparierte Einzelzeile – gegen `podman-network.unit(5)` verifiziert.

Beispiel für `quadlet.network({ name: "app", internal: true, subnet: "10.89.0.0/24",
gateway: "10.89.0.1", label: { env: "prod" } })`:

```
[Unit]
Description=Podman network: app

[Network]
NetworkName=app
Internal=true
Subnet=10.89.0.0/24
Gateway=10.89.0.1
Label=env=prod
```

### Kanonische Key-Namen (gegen Podman-Doku verifiziert)

Die `[Network]`-Keys `NetworkName`, `Driver`, `IPAMDriver`, `Internal`, `IPv6`, `DisableDNS`,
`Subnet`, `Gateway`, `IPRange`, `DNS`, `Options`, `Label`, `PodmanArgs` entsprechen der
`podman-systemd.unit(5)` / `podman-network.unit(5)`-Dokumentation (via Context7 aus dem aktuellen
Podman-Repo bestätigt).

### Edge Cases

- **Nur `name` gesetzt:** Erzeugt eine gültige Unit mit `[Unit] Description=Podman network: <name>`
  und `[Network] NetworkName=<name>`. Podman verwendet Standard-Bridge und -Subnet.
- **`internal: false` explizit:** `Internal=false` wird geschrieben (nicht weggelassen), da
  `maybeRenderQuadletBool` nur bei `undefined` auslässt – konsistent mit dem container-Modul.
- **Leere `label`/`options`-Records:** Keine Zeilen (via `renderQuadletKeyValue` über leerem Record).
- **Steuerzeichen in einem Wert:** Wird beim Rendern über `renderQuadletLine` abgelehnt (Wurf beim
  Modulaufbau, nicht erst beim Apply) – identisch zum container-Verhalten.
- **Symlink am Ziel-Pfad:** `applyQuadletFile`/`checkQuadletFile` verweigern das Schreiben durch einen
  Symlink bzw. behandeln ihn als `needs-apply` – geerbt, ohne Zusatzcode.
- **`name` referenziert Traversal (`..`, reiner Punkt, führendes `-`):** Durch `validateQuadletName`
  abgelehnt.
- **Geändertes `subnet`/`gateway`/… an bereits laufendem Netzwerk:** Podman legt ein Netzwerk genau
  einmal an. `daemon-reload` regeneriert nur die Unit; das Live-Netzwerk übernimmt geänderte Parameter
  **nicht** automatisch, bis es entfernt (und beim nächsten Container-Start neu angelegt) wird. Das
  Modul gibt in diesem Fall den unter „Warn-Detail" beschriebenen Hinweis aus, unternimmt aber selbst
  **keine** Neuanlage (nicht-destruktiv, deckt sich mit der container-Semantik und der Issue-Garantie).
- **`podman` auf dem Host nicht verfügbar:** Die Existenz-Probe für den Warn-Detail scheitert
  (Exit ≠ 0); der Hinweis entfällt, `apply` bleibt erfolgreich – der eigentliche Unit-Write hängt
  nicht von `podman` ab.

## Akzeptanzkriterien

- [ ] `quadlet.network(options)` existiert als Modul-Methode; `pnpm agent:check` (Typecheck, Lint,
      Build) im Paket `paratix` läuft grün.
- [ ] Für das Beispiel aus „Reihenfolge der `[Network]`-Zeilen" (`name: "app"`, `internal: true`,
      `subnet`, `gateway`, `label`) erzeugt das Modul exakt den dort gezeigten Unit-Text
      (verifiziert durch einen Content-Assertion-Test).
- [ ] Die Datei wird nach `/etc/containers/systemd/app.network` geschrieben; `apply` löst bei
      Content-Änderung `systemctl daemon-reload` aus, bei unverändertem Content und gesetztem
      Reload-Flag meldet `check` `ok` (Idempotenz), sonst `needs-apply`.
- [ ] `apply` liefert `changed` beim Erstellen/Ändern; ein zweiter `check`-Lauf gegen identischen
      On-Disk-Content plus vorhandenes Flag liefert `ok`.
- [ ] Ungültiger `name` (führendes `-`, reiner Punkt, Traversal) sowie ein Steuerzeichen in einem
      Wert werfen beim Modulaufbau einen Fehler.
- [ ] Die Felder `ipv6`, `dns` und `ipamDriver` erzeugen die Zeilen `IPv6=`, `DNS=` (je Eintrag)
      und `IPAMDriver=` in der oben definierten Reihenfolge.
- [ ] Existiert auf dem Host ein Netzwerk mit gleichem `NetworkName` und ändert sich der Unit-Content,
      enthält das `changed`-`ModuleResult` den Warn-Detail; existiert kein solches Netzwerk oder ist
      `podman` nicht verfügbar, erscheint kein Hinweis und `apply` bleibt erfolgreich.
- [ ] Fehlermeldungen für Netzwerk-Fehler nennen `quadlet.network` (nicht `quadlet.container`).
- [ ] `llm-guide.md` enthält eine `quadlet.network`-Zeile in der Modultabelle.

## Validierungsplan

- **Unit-Tests** in `test/modules/quadlet.test.ts` mit `createMockSsh` analog zu den vorhandenen
  container-Tests:
  - Content-Assertion für den vollständigen Unit-Text (alle Optionen und Reihenfolge).
  - Content-Assertion für den Minimalfall (`name`-only).
  - `apply` schreibt in den korrekten Pfad `/etc/containers/systemd/<name>.network`, ruft
    `daemon-reload` und persistiert das `quadlet-network-`-Flag.
  - `check` liefert `ok` bei passendem Content + Flag, `needs-apply` bei fehlendem Flag, fehlender
    Datei oder Content-Drift.
  - `_applyDryRun` liefert einen Unified-Diff bzw. den `(dry-run, daemon-reload pending)`-Detailhinweis
    analog container.
  - Validierungs-Wurf-Tests für ungültigen `name` und Steuerzeichen im Wert.
  - Determinismus-Test: `label`/`options` werden alphabetisch nach Schlüssel sortiert ausgegeben.
  - Content-Test für die Zusatzfelder `ipv6`, `dns` (mehrere Server) und `ipamDriver` inkl. korrekter
    Zeilen-Reihenfolge.
  - Warn-Detail-Test mit `createMockSsh`: `podman network exists`-Aufruf liefert Exit 0 → Content-Change
    ergibt `changed` mit Warn-Detail; Exit ≠ 0 → `changed` ohne Hinweis; die Existenz-Probe darf `apply`
    bei fehlendem `podman` nicht scheitern lassen.
- **Voller Paket-Check:** `pnpm agent:check` (gemäß `AGENTS.md` der Check-Befehl; **nicht** bei
  `git commit`).

## Annahmen und offene Punkte

- **Annahme:** Die Container-Referenz (`networks: ["app.network"]`) funktioniert bereits über die
  vorhandene `networks`-Option von `quadlet.container` (Issue bestätigt); es sind **keine** Änderungen
  am container-Modul nötig. Verifizierter Kontext: `buildQuadletNetworkLines` in `quadletHelpers.ts`
  rendert `Network=`-Zeilen bereits unverändert aus `options.networks`.
- **Annahme:** Kein `quadlet.volume`-Modul (Issue-Scope-Note: named volumes funktionieren per
  Referenz ohne Modul).
- **Annahme:** `description` als Zusatzoption ist gewünscht (folgt aus Variante A); falls nicht
  gewünscht, kann die Option entfallen und die Description bleibt beim Default.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       2 |
| Testbarkeit |        0 |       0 |       0 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- **Scope (Hinweis, im Review entschieden):** Die Feld-Menge wurde bewusst über die Issue-API hinaus
  um `ipv6`, `dns` und `ipamDriver` erweitert (User-Entscheidung im vertieften Plan-Review). Additiv,
  keine Verhaltensänderung bei Nichtnutzung.
- **Fehlerfälle (Hinweis, im Review entschieden):** Bei geändertem Content und bereits existierendem
  Live-Netzwerk gibt das Modul einen read-only ermittelten Warn-Detail aus, statt eine destruktive
  Neuanlage zu erzwingen. Non-fatal, wenn `podman` fehlt.
- **Fehlerfälle (Hinweis):** Der `label`-Parameter in `applyQuadletFile`/`checkQuadletFile` muss
  additiv mit Default `quadlet.container` eingeführt werden, damit die Bestandsaufrufe und deren
  Test-Erwartungen (exakte Fehlermeldungs-Strings) unverändert bleiben. Der Umsetzer prüft die
  vorhandenen container-Fehlermeldungs-Tests auf Regression.
- **Architektur (Hinweis):** `buildQuadletContainerDryRunDiff` ist bereits generisch über
  `filePath`/`desired` und wird wiederverwendet. Optionale neutrale Umbenennung (z. B.
  `buildQuadletDryRunDiff`) verbessert die Lesbarkeit, ist aber kein Muss und erweitert den Scope
  nicht.
- **Wartbarkeit (Hinweis):** Die Steuerzeichen-Fehlermeldung in `assertQuadletLineValue` lautet
  hartkodiert `quadlet.container …`. Für ein Netzwerk-Feld ist das eine leicht irreführende, aber
  rein interne Meldung. Optionale Neutralisierung des Präfixes auf `quadlet` möglich; nicht kritisch,
  kein Blocker.

## Offene Punkte

- Keine offenen Punkte.

## Testergebnisse

**Datum:** 2026-07-15
**Ergebnis:** Bestanden

- `pnpm agent:check` (Lint via oxlint + eslint, Prettier-Format-Check, Typecheck, Build, Unit- und
  Distribution-Tests) läuft im Worktree vollständig grün (Exit 0).
- Neue Unit-Tests in `packages/paratix/test/modules/quadlet.test.ts` (17 Fälle für `quadlet.network`):
  vollständige Zeilenreihenfolge inkl. `ipv6`/`dns`/`ipamDriver`, Minimalfall, `apply` schreibt in
  `/etc/containers/systemd/<name>.network` mit `daemon-reload` und `quadlet-network-`-Flag, Warn-Detail
  bei existierendem Live-Netzwerk (und dessen Ausbleiben ohne Netzwerk), `check` ok/needs-apply
  (fehlendes Flag, fehlende Datei, Content-Drift), `_applyDryRun` mit Diff und Warn-Detail,
  Validierungs-Würfe (ungültiger Name, Steuerzeichen), Sortierung von `Label`/`Options`,
  Flag-Namespace-Trennung gegenüber `quadlet.container`. Alle 74 Tests der Datei grün.

## Review-Findings

**Datum:** 2026-07-15
**Reviewer:** nodejs-reviewer

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      3 |
| Offen / Nicht umgesetzt |      0 |

Keine kritischen oder wichtigen Findings. Drei Hinweise (alle Komplexität „Leicht") wurden direkt
umgesetzt: H1 – Steuerzeichen-Fehlermeldung im geteilten Renderer auf neutrales `quadlet`-Präfix
umgestellt; H2 – expliziter `check`-Content-Drift-Test für `quadlet.network` ergänzt; H3 –
Regressionstest für die Reload-Flag-Namespace-Trennung `quadlet-network-` vs. `quadlet-container-`
ergänzt. Der Reviewer bestätigte, dass die `quadlet.container`-Laufzeitpfade unverändert bleiben
(Label-Default, Reload-Flag-Präfix). Kein externer Review-Report nötig.
