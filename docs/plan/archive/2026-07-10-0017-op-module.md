# 0017 — op-Modul (1Password Secret-Auflösung)

## Anforderung

Implementierung des `op`-Moduls gemäß Spezifikation in `docs/module.md` (Zeilen 496–588).
Das Modul löst `op://`-Referenzen über die 1Password CLI lokal auf dem Controller auf
und stellt die Secrets als `meta`-Werte für nachfolgende Module bereit.

## Architekturentscheidungen

- **Erstes lokales Modul:** `local: true` — kein SSH, `apply()` und `check()` erhalten `ssh = null`
- **TOTP ohne externe Dependency:** RFC 6238 TOTP-Berechnung mit `node:crypto` (HMAC-SHA1, Base32-Decoding, Dynamic Truncation) in eigener Datei `src/totp.ts`
- **`execFileSync` statt `execSync`:** Verhindert Command Injection — keine Shell-Interpretation der Reference-Strings
- **Input-Validierung:** Alle References müssen mit `op://` beginnen (Fehler zur Konstruktionszeit)
- **OTP-Erkennung:** RegExp `/\/(?:one-time-password|otp)$/iv` auf der URI-Endung
- **Lazy OTP-Funktionen:** OTP-Werte werden als `() => string` in `meta` geschrieben — TOTP-Code wird erst bei Zugriff berechnet (30s Gültigkeit)

## Betroffene Dateien

| Aktion | Datei                     | Beschreibung                             |
| ------ | ------------------------- | ---------------------------------------- |
| Neu    | `src/modules/op.ts`       | op.resolve() Modul                       |
| Neu    | `src/totp.ts`             | TOTP-Berechnung (RFC 6238)               |
| Neu    | `test/modules/op.test.ts` | 19 Tests für op-Modul                    |
| Neu    | `test/totp.test.ts`       | 14 Tests für TOTP                        |
| Edit   | `src/modules/index.ts`    | Export hinzugefügt                       |
| Edit   | `cspell.json`             | Wörter "otpauth", "totp", "hotp" ergänzt |

## Implementierungsdetails

### op.resolve(references)

- Parameter: `Record<string, string>` — Keys = Env-Namen, Values = `op://`-URIs
- Validierung: alle Values müssen mit `op://` beginnen (wirft zur Konstruktionszeit)
- `check()` → immer `"ok"` (reines Lesen, keine Serveränderung)
- `apply()`:
  1. References in reguläre vs. OTP splitten
  2. Reguläre: `execFileSync("op", ["inject"], { input: JSON.stringify(entries) })` (Batch)
  3. OTP: `execFileSync("op", ["read", reference])` → `otpauth://` URI → lazy `() => generateTotpCode(uri)`
  4. Return `{ status: "ok", meta: { ...regular, ...otp } }`
  5. Bei Fehler: `{ status: "failed" }`

### TOTP (totp.ts)

- `generateTotpCode(otpauthUri: string): string`
- Parst `secret`, `period` (default 30), `digits` (default 6) aus URI
- Base32-Decoding → HMAC-SHA1 → Dynamic Truncation → 6-stelliger Code

## Testergebnisse

- 641 Tests gesamt (19 op + 14 totp + 608 bestehend)
- 0 Lint-Errors, TypeScript + Prettier + Build bestanden
- RFC 6238 Testvektoren verifiziert (t=59 → 287082, t=1111111109, t=1111111111, t=2000000000)

## Review-Findings und Behebung

| Finding                                             | Schweregrad | Behebung                                     |
| --------------------------------------------------- | ----------- | -------------------------------------------- |
| Command Injection via `op read` Shell-Interpolation | Kritisch    | `execSync` → `execFileSync` (kein Shell)     |
| Fehlende Input-Validierung (`op://` Prefix)         | Wichtig     | `validateReferences()` zur Konstruktionszeit |
| Tests rufen lazy OTP-Funktion nie auf               | Wichtig     | Neuer Test prüft 6-Digit-Rückgabe            |
| SHA-1-only TOTP                                     | Hinweis     | Akzeptiert — 1Password nutzt SHA-1           |
| Case-insensitive OTP-Erkennung                      | Hinweis     | Defensiv sinnvoll, kein Change               |
