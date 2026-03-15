# 0028: files-Feld in paratix

## Anforderung

Das publizierte npm-Paket `paratix` soll auf die relevanten Dateien beschränkt werden, analog zum bereits umgesetzten `files`-Feld in `create-paratix` (Commit `abdb6e4`). Zusätzlich soll `llm-guide.md` im Paket enthalten sein und in der README darauf verwiesen werden.

## Architekturentscheidungen

- **`files`-Feld:** `["dist", "llm-guide.md"]` — `dist/` deckt alle Exports und das CLI-Binary ab, `llm-guide.md` wird auf Wunsch des Nutzers für LLM-basierte Codegenerierung mitgeliefert.
- **npm-Automatik:** `package.json` und `README.md` werden von npm automatisch inkludiert und müssen nicht im `files`-Feld stehen.
- **Platzierung:** Das `files`-Feld wurde nach `license` eingefügt (am Ende der package.json). Abweichung von `create-paratix`, wo es nach `type` steht — funktional identisch.

## Betroffene Dateien

| Datei                           | Änderung                                      |
| ------------------------------- | --------------------------------------------- |
| `packages/paratix/package.json` | `"files": ["dist", "llm-guide.md"]` eingefügt |
| `packages/paratix/README.md`    | "LLM Guide"-Abschnitt vor License ergänzt     |

## Implementierungsdetails

### package.json

Neues Feld nach `license`:

```json
"files": [
  "dist",
  "llm-guide.md"
]
```

### README.md

Neuer Abschnitt vor "License":

```markdown
## LLM Guide

This package includes an `llm-guide.md` file that provides detailed information
for writing Paratix modules and playbooks. It covers the complete API reference,
code patterns, and common mistakes to avoid. When using an LLM to generate
Paratix code, point it at this file for best results.
```

## Testergebnisse

- **Tarball-Inhalt:** Verifiziert — enthält nur `dist/`, `llm-guide.md`, `package.json`, `README.md`
- **pnpm agent:check:** 10 vorbestehende Lint-Fehler in Testdateien (nicht durch diese Änderungen verursacht)

## Review-Findings

| ID    | Schweregrad | Bereich       | Status             |
| ----- | ----------- | ------------- | ------------------ |
| R-001 | Hinweis     | Code-Qualität | ⏳ Nicht umgesetzt |
| R-003 | Hinweis     | Dokumentation | ⏳ Nicht umgesetzt |

- **R-001:** `files`-Feld steht an anderer Position als in `create-paratix` — kosmetisch
- **R-003:** Kein Pfad-Hinweis (`node_modules/paratix/llm-guide.md`) im README — optional
