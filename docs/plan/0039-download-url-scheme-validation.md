# 0039 — URL-Schema-Validierung für download.url() und download.large()

## Anforderung

Ergänze eine URL-Schema-Validierung für `download.url()` und `download.large()` in `download.ts`. Nur `http://` und `https://` sollen erlaubt sein. Bei anderen Schemas (`file://`, `gopher://`, `dict://`) soll ein klarer Fehler geworfen werden.

## Architekturentscheidungen

- **Allowlist-Strategie:** Nur `http:` und `https:` erlauben statt gefährliche Schemes zu blocken — sicherer, da neue Schemes automatisch abgelehnt werden
- **Validierung im Konstruktor:** Synchron beim Erstellen des Moduls, nicht erst beim Apply — konsistent mit `download.github()` und ermöglicht frühes Scheitern
- **Platzierung in `netHelpers.ts`:** Netzwerkbezogene Validierung gehört zu den bestehenden Header-Validierungsfunktionen
- **`new URL()` zum Parsen:** Validiert gleichzeitig die URL-Syntax und ermöglicht saubere Protocol-Prüfung
- **`download.github()` nicht angepasst:** URL wird intern als `https://github.com/...` konstruiert, kein User-Input

## Betroffene Dateien

| Datei                                            | Änderung                                                    |
| ------------------------------------------------ | ----------------------------------------------------------- |
| `packages/paratix/src/modules/netHelpers.ts`     | Neue `validateHttpUrl(url)` Funktion mit JSDoc              |
| `packages/paratix/src/modules/download.ts`       | Import + Aufrufe in `download.url()` und `download.large()` |
| `packages/paratix/test/modules/download.test.ts` | 12 neue Tests (6 pro Modul)                                 |

## Implementierungsdetails

### `validateHttpUrl(url: string): void`

- Parst URL mit `new URL(url)` — wirft bei ungültiger Syntax
- Prüft `parsed.protocol !== "https:" && parsed.protocol !== "http:"`
- Fehlermeldung enthält das ungültige Schema und die URL

### Integration

- `download.large()`: Aufruf direkt am Anfang, vor `createHash`
- `download.url()`: Aufruf direkt am Anfang, vor `resolvedOptions`

## Testergebnisse

12 neue Tests, alle bestanden:

- `file:///etc/passwd` → wirft
- `ftp://example.com/file` → wirft
- `gopher://evil.com` → wirft
- `not-a-url` (ungültige Syntax) → wirft
- `https://example.com/file` → akzeptiert
- `http://example.com/file` → akzeptiert

Gesamtergebnis: 1172 Tests bestanden, 0 Fehler.

## Review-Findings

| ID    | Schweregrad | Bereich                            | Status                      |
| ----- | ----------- | ---------------------------------- | --------------------------- |
| R-001 | Hinweis     | Code-Qualität (v-Flag)             | Kein Handlungsbedarf        |
| R-002 | Hinweis     | Security (URL-Länge in Meldung)    | Kein Handlungsbedarf        |
| R-003 | Wichtig     | Security (github ohne Validierung) | Bewusste Designentscheidung |
| R-004 | Hinweis     | Code-Qualität (Test-Duplikation)   | Optional                    |
| R-005 | Hinweis     | Security (Allowlist korrekt)       | Positiv-Befund              |
| R-006 | Hinweis     | API Design (Fehlermeldung)         | Optional                    |
