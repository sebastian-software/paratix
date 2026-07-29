# 0030 Root README Enhancement

## Anforderung

Root-README.md für das Monorepo erweitern mit:

- Überblick über das Projekt
- Links zu packages/paratix und packages/create-paratix
- Homepage https://paratix.oss.sebastian-software.com
- Copyright Sebastian Software GmbH

## Betroffene Dateien

- `README.md` (Root)

## Implementierung

### 1. Homepage- und GitHub-Links

Zeile 3: `[Homepage](https://paratix.oss.sebastian-software.com) · [GitHub](https://github.com/sebastian-software/paratix)`

### 2. Packages-Tabelle

Neue Sektion nach dem Intro mit Tabelle der beiden Monorepo-Pakete und relativen Links zu den Package-Verzeichnissen.

### 3. Copyright

License-Abschnitt erweitert: `MIT — Copyright 2026 Sebastian Software GmbH` mit Link zur Firmenwebsite (sebastian-software.com).

### 4. Typo-Fix

Nebenbei korrigiert: "a already" → "an already" (Grammatik).

## Review-Findings

- **R-001 (Hinweis, behoben):** Copyright-Link Domain war `.de` statt `.com` — korrigiert auf `.com` (konsistent mit package.json und Commit f0dfc27)
- **R-002 (Hinweis, behoben):** Fehlende Newline am Dateiende — durch Prettier automatisch behoben

## Validierung

- Prettier: ✅ bestanden
- TypeScript: ✅ bestanden
- Tests: ✅ 838 Tests bestanden
- Lint: ⚠️ Pre-existierende Fehler in Test-Dateien (nicht durch diese Änderung verursacht)
