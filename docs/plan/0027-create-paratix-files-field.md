# 0027 — `files`-Feld in create-paratix package.json

## Anforderung

Das npm `files`-Feld in `packages/create-paratix/package.json` hinzufügen, um beim `npm publish` nur die benötigten Build-Artefakte (`dist/`) ins Package aufzunehmen. Ohne dieses Feld wird alles inkludiert (Source, Tests, Configs), was das Package unnötig aufbläht.

## Architekturentscheidungen

- **`"files": ["dist"]`** reicht aus, da alle Templates als String-Konstanten inline in `src/index.ts` definiert sind und von tsup in `dist/index.js` gebundelt werden. Es gibt keine externen Template-Dateien oder Assets.
- `package.json`, `README.md` und `LICENSE` werden von npm automatisch inkludiert.
- Platzierung: nach `"type"`, vor `"bin"` — folgt gängiger Konvention.

## Betroffene Dateien

| Datei                                  | Änderung                        |
| -------------------------------------- | ------------------------------- |
| `packages/create-paratix/package.json` | `"files": ["dist"]` hinzugefügt |

## Testergebnisse

- TypeScript: 0 Fehler
- Tests: 12/12 bestanden (create-paratix), 838/838 bestanden (paratix)
- Formatting: Bestanden
- Lint: 10 pre-existierende Fehler (nicht durch Änderung verursacht)

## Review-Findings

| ID    | Titel                                    | Schweregrad | Status                                          |
| ----- | ---------------------------------------- | ----------- | ----------------------------------------------- |
| R-001 | Fehlende LICENSE-Datei auf Package-Ebene | Hinweis     | ⏳ Nicht umgesetzt (nicht Teil der Anforderung) |
