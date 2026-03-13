# 0003 — apt-Modul vervollständigen

## Anforderung

Das bestehende `apt`-Modul um die drei fehlenden Methoden `apt.key`, `apt.repository` und `apt.debconf` erweitern, sodass der vollständige APT-Workflow abgebildet ist: GPG-Key importieren → Repository hinzufügen → Pakete vorkonfigurieren → installieren.

## Architekturentscheidungen

- **Kein neues Modul:** Alle drei Methoden werden als neue Methoden zum bestehenden `apt`-Objekt in `packages/paratix/src/modules/apt.ts` hinzugefügt (alphabetisch sortiert).
- **Helper-Funktionen:** Komplexe Logik wurde in Top-Level-Funktionen extrahiert (`buildPpaRepository`, `injectSignedBy`, `parseDebconfOutput`, `resolveDebconfType`), um Lint-Limits für Funktionslänge einzuhalten.
- **PPA + Standard:** `apt.repository` unterstützt beide Formen über eine einzige Methode mit optionalem `source`-Parameter. PPA wird erkannt wenn der erste Parameter mit `ppa:` beginnt.
- **signed-by Auto-Derivation:** Wenn kein expliziter `signedBy`-Wert angegeben wird, leitet `apt.repository` den Key-Pfad automatisch vom Repository-Namen ab (`/etc/apt/keyrings/<name>.gpg`). Kann mit `signedBy: false` deaktiviert werden.
- **Auto-Update:** `apt.repository` führt nach dem Hinzufügen automatisch `apt-get update` aus.
- **debconf Record-API:** `apt.debconf` nutzt eine einfache `Record<string, string>`-API. Der debconf-Typ wird automatisch per `debconf-communicate METAGET` ermittelt (Fallback: `"string"`).

## Betroffene Dateien

| Datei                                       | Änderung                                                              |
| ------------------------------------------- | --------------------------------------------------------------------- |
| `packages/paratix/src/modules/apt.ts`       | 3 neue Methoden, 4 Helper-Funktionen                                  |
| `packages/paratix/test/modules/apt.test.ts` | 18 neue Tests in 4 describe-Blöcken                                   |
| `cspell.json`                               | 4 neue Wörter (dearmor, debconf, keyrings, metaget, nodistro, ondrej) |

## Implementierungsdetails

### apt.key(name, url)

- Check: `[ -f /etc/apt/keyrings/<name>.gpg ]`
- Apply: `mkdir -p /etc/apt/keyrings && curl -fsSL <url> | gpg --dearmor --yes -o /etc/apt/keyrings/<name>.gpg`

### apt.repository(nameOrPpa, source?, options?)

- **PPA-Form:** `add-apt-repository -y <ppa>`, Check via `grep -rq` in sources.list.d
- **Standard-Form:** Schreibt nach `/etc/apt/sources.list.d/<name>.list` mit optionalem signed-by, dann `apt-get update`
- Validierung: `source` ist Pflichtfeld für Nicht-PPA-Repos (wirft Error)
- `injectSignedBy` prüft auf bereits vorhandenes `signed-by` um Duplikate zu vermeiden

### apt.debconf(pkg, selections)

- Check: `debconf-show <pkg>` parsen und Werte vergleichen
- Apply: Typ per `debconf-communicate METAGET` ermitteln, dann `debconf-set-selections`
- Validierung: Newlines in Question-Keys und Values werden abgelehnt

## Testergebnisse

- 25 Tests in `apt.test.ts` (7 bestehend + 18 neu)
- 108 Tests gesamt im paratix-Package
- Alle Tests bestanden

## Review-Findings und Behebung

| Finding                                           | Schweregrad | Behebung                                               |
| ------------------------------------------------- | ----------- | ------------------------------------------------------ |
| `gpg --dearmor` blockiert bei existierender Datei | WICHTIG     | `--yes` Flag hinzugefügt                               |
| Newline-Injection in debconf-Selections           | WICHTIG     | Validierung mit early-return `{ status: "failed" }`    |
| Fehlende source-Validierung in repository         | WICHTIG     | `throw new Error()` für Nicht-PPA ohne source          |
| Doppeltes signed-by möglich                       | HINWEIS     | Check auf bestehendes `signed-by=` in `injectSignedBy` |
