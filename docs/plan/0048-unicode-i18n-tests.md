# 0048: Unicode- und I18N-Tests fuer Datei-, Template-, Block- und SFTP-Pfade

## Anforderung

Paratix hatte bislang fuer kritische Datei- und SSH-Pfade praktisch keine explizite Abdeckung fuer Unicode- und Internationalisierungsfaelle. Ziel war, gezielte Unit- und Integrationsfaelle fuer nicht-ASCII-Inhalte und Dateinamen zu ergaenzen, damit Encoding- und Shell-Quoting-Probleme reproduzierbar abgesichert sind.

Scope:

- `file.copy`
- `file.template`
- `file.block`
- SFTP Upload/Download
- echte Integrationsfaelle mit nicht-ASCII-Inhalten und Dateinamen

## Architekturentscheidungen

- **Gezielte Regressionen statt breitem I18N-Testframework**: Der Ausbau bleibt bewusst auf die im Review genannten Risikopfade begrenzt. Das haelt die Suite lesbar und verhindert Over-Engineering.
- **Unicode-Inhalt und Unicode-Pfade getrennt und kombiniert pruefen**: Die neuen Faelle testen sowohl nicht-ASCII-Inhalte als auch nicht-ASCII-Dateinamen/Pfade, weil Shell-Quoting- und Encoding-Fehler haeufig erst in der Kombination sichtbar werden.
- **Live-Host-Verifikation fuer echte Risikopfade**: Die Integrationssuite prueft nicht nur erfolgreiche Modul-Ausfuehrung, sondern den realen Endzustand auf dem SSH-Testserver via `readFile`, Dateinamen und Marker-Inhalte.
- **ASCII-Default im Produktivcode bleibt unberuehrt**: Es wurden ausschliesslich Tests erweitert; keine Produktionslogik musste fuer diesen Ausbau geaendert werden.

## Betroffene Dateien

| Datei                                                           | Beschreibung                                                                                   |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `packages/paratix/test/modules/file.test.ts`                    | Neue Unicode-Unit-Tests fuer `file.copy`, `file.template` und `file.block`                     |
| `packages/paratix/test/sftp.test.ts`                            | Neue Unicode-Unit-Tests fuer SFTP-Upload und -Download mit nicht-ASCII-Pfaden                  |
| `packages/paratix/test/integration/paratix.integration.test.ts` | Echte Unicode-Integrationsfaelle fuer SFTP sowie `file.copy`, `file.template` und `file.block` |
| `review-report-2026-03-19.md`                                   | Review-Finding R-003 als umgesetzt markiert                                                    |

## Implementierungsdetails

### Unit-Tests

- `file.copy` prueft jetzt Uploads mit Unicode-Inhalt und Unicode-Remote-Pfad
- `file.template` prueft Unicode-Template-Inhalt und Unicode-Environment-Werte
- `file.block` prueft Unicode-Blockinhalt und Unicode-Dateipfad
- `sftpDownload` und `sftpUpload` pruefen nicht-ASCII-Remote- und Local-Pfade explizit auf den exakten Uebergabewerten

### Integrationsfaelle

- **Unicode-SFTP**:
  - echter Upload mit Unicode-Dateiname und Unicode-Inhalt
  - echter Download mit Unicode-Dateiname und Unicode-Inhalt
- **Unicode-Dateimodule**:
  - `file.directory` auf Unicode-Pfadsegment
  - `file.copy` mit Unicode-Dateiname und Inhalt
  - `file.template` mit Unicode-Werten
  - `file.block` mit Unicode-Inhalt und Unicode-Dateiname
  - anschliessende Verifikation ueber echte Remote-Dateiinhalte und `check()`-Konformitaet

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/modules/file.test.ts test/sftp.test.ts`
- `pnpm --filter paratix test:integration`
- `pnpm agent:check`
- `pnpm agent:check:integration`

## Review-Findings und deren Behebung

- **Behoben**: Review-Finding R-003 zu fehlender Unicode-/I18N-Abdeckung in Datei-, Template-, Block- und SFTP-Pfaden.
- **Offen**: Keine weiteren Findings aus diesem Scope.
