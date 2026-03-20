# 0049: Sichere Bootstrap-Defaults für create-paratix

## Anforderung

Das Scaffold von `create-paratix` soll nicht mehr stillschweigend auf dauerhaftem Root-SSH basieren. Der Standardpfad soll einen dedizierten Admin-User und einen klar gehärteten Endzustand erzeugen. Ein Root-Bootstrap-Pfad bleibt nur als explizit auswählbarer Übergangsmodus erhalten.

## Architekturentscheidungen

- `create-paratix` unterstützt jetzt zwei explizite Scaffold-Modi:
  - `hardened-admin` als sicherer Default
  - `bootstrap-root` als bewusst temporärer Übergangsmodus
- Die Template-Erzeugung wird zentral über `createServerTemplate(mode)` gesteuert, statt einen einzigen starren `server.ts`-String zu pflegen.
- Die CLI parst `--bootstrap-root` explizit und verwendet ohne Flag immer den gehärteten Admin-Default.
- Der gehärtete Default verbindet sich als dedizierter Admin-User und deaktiviert Root-Login final mit `PermitRootLogin: "no"`.
- Der Root-Bootstrap-Modus bleibt im Template sichtbar als Übergang markiert und belässt Root-Login nur vorübergehend auf `prohibit-password`.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `packages/create-paratix/src/index.ts`       | Neue Scaffold-Modi, Template-Builder, CLI-Argument-Parsing und Weitergabe des Modus in die Projektgenerierung |
| `packages/create-paratix/test/index.test.ts` | Regressionstests für Default-Modus, Bootstrap-Root-Modus und CLI-Argument-Parsing                             |
| `packages/create-paratix/README.md`          | Dokumentation des sicheren Defaults und des expliziten `--bootstrap-root`-Übergangsmodus                      |

## Implementierungsdetails

- Das Standard-Template erzeugt jetzt:
  - `adminUser = "admin"`
  - `ssh.user = adminUser`
  - `user.present(adminUser, { groups: ["sudo"], shell: "/bin/bash" })`
  - `ssh.authorizedKeys(adminUser, adminPublicKey)`
  - `PermitRootLogin: "no"`
- Der explizite Bootstrap-Root-Modus erzeugt:
  - `ssh.user = "root"`
  - Provisionierung desselben dedizierten Admin-Users
  - klar kommentierten Übergangspfad
  - `PermitRootLogin: "prohibit-password"` bis zum Wechsel auf den Admin-User
- Die Tests decken beide generierten Templates sowie das neue CLI-Parsing für `--bootstrap-root` ab.

## Testergebnisse

- `pnpm --filter create-paratix test`
- `pnpm --filter create-paratix exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen internen Review-Findings nach der Umsetzung.
