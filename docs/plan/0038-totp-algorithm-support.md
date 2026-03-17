# 0038 TOTP Algorithm Support

## Anforderung

Die TOTP-Implementierung unterstützte nur SHA1 und ignorierte den `algorithm`-Parameter aus der otpauth-URI. Feature: `algorithm`-Parameter auswerten (SHA1, SHA256, SHA512), an `createHmac` übergeben, bei unbekanntem Algorithmus Fehler werfen.

## Architekturentscheidungen

- **Allowlist-Ansatz:** `SUPPORTED_ALGORITHMS` Record mappt URI-Namen (SHA1, SHA256, SHA512) auf Node.js crypto Hash-Namen (sha1, sha256, sha512). Neue Algorithmen können durch Ergänzung des Records hinzugefügt werden.
- **Case-insensitive:** Der `algorithm`-Parameter wird vor dem Lookup zu uppercase konvertiert, um Varianten wie `sha256`, `Sha256`, `SHA256` gleich zu behandeln.
- **Separate `parseAlgorithm` Funktion:** Ausgelagert aus `parseTotpParameters` um das `max-statements` Lint-Limit (15) einzuhalten.
- **Default SHA1:** Rückwärtskompatibel — ohne `algorithm`-Parameter wird SHA1 verwendet.

## Betroffene Dateien

- `packages/paratix/src/totp.ts` — Neue Konstante `SUPPORTED_ALGORITHMS`, neue Funktion `parseAlgorithm`, `parseTotpParameters` erweitert, `generateTotpCode` verwendet dynamischen Algorithmus
- `packages/paratix/test/totp.test.ts` — 7 neue Tests (5 für algorithm-Parameter, 2 für error handling)

## Implementierungsdetails

1. `SUPPORTED_ALGORITHMS` als `Record<string, string>` mit SHA1→sha1, SHA256→sha256, SHA512→sha512
2. `parseAlgorithm(url)` extrahiert und validiert den Parameter, wirft bei unbekanntem Algorithmus
3. `parseTotpParameters` gibt `algorithm` im Return-Objekt zurück
4. `generateTotpCode` destructured `algorithm` und übergibt es an `createHmac(algorithm, key)`

## Testergebnisse

- 1137 Tests bestanden (1118 paratix + 19 create-paratix)
- 28 TOTP-Tests (14 bestehend + 7 parameter validation + 7 algorithm)
- 0 Lint-Fehler, 0 TypeScript-Fehler

## Review-Findings

| ID    | Titel                                       | Schweregrad | Status  |
| ----- | ------------------------------------------- | ----------- | ------- |
| R-001 | Veralteter JSDoc bei truncateHmac           | Hinweis     | Behoben |
| R-002 | Fehlende RFC-Testvektoren für SHA256/SHA512 | Wichtig     | Offen   |
| R-004 | Record statt as const                       | Hinweis     | Offen   |
