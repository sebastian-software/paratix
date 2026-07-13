# Plan 0085: create-paratix Admin-Public-Key-Validierung härten

## Anforderung

Die Admin-Public-Key-Validierung von `create-paratix` soll OpenSSH-Public-Keys strenger prüfen. RSA-Schlüssel müssen konkrete Parametergrenzen erfüllen, ECDSA-Punkte müssen kryptografisch auf der deklarierten OpenSSH-kompatiblen Kurve liegen, Security-Key-ECDSA für `nistp256` muss unterstützt bleiben und Regressionstests sollen die relevanten Fehlerfälle abdecken.

## Architekturentscheidungen

- Die Wire-Blob-Prüfung bleibt zentral in `packages/create-paratix/src/openSshPublicKeyWire.ts`, damit direkte CLI-Werte, Dateien und lokal entdeckte `.pub`-Dateien dieselben Regeln verwenden.
- RSA-`mpint`-Werte werden nach OpenSSH-Decoding auf positive Werte geprüft. Der Exponent muss ungerade und mindestens `3` sein, der Modulus mindestens `2048` Bit.
- ECDSA-Punkte behalten die bestehenden Strukturprüfungen für Algorithmus, Kurvenname, unkomprimierten Punkt und erwartete Länge. Danach validiert Node `crypto.createPublicKey` die Koordinaten über JWK-Kurven `P-256`, `P-384` und `P-521`.
- `sk-ecdsa-sha2-nistp256@openssh.com` bleibt erlaubt und nutzt dieselbe P-256-Punktvalidierung plus den bestehenden Application-String.

## Betroffene Dateien

| Datei                                                 | Beschreibung                                                                                     |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `packages/create-paratix/src/openSshPublicKeyWire.ts` | RSA-Parameterprüfung und kryptografische ECDSA-Punktvalidierung                                  |
| `packages/create-paratix/test/index.test.ts`          | Regressionstests für gültige RSA/ECDSA/Security-Key-Schlüssel und ungültige RSA-/ECDSA-Parameter |

## Implementierungsdetails

- Neue RSA-Helfer normalisieren positives `mpint`-Sign-Padding, berechnen Bitlängen und prüfen Exponenten als `bigint`.
- Die ECDSA-Prüfung teilt den unkomprimierten Punkt in `x` und `y` auf und übergibt die Koordinaten Base64URL-kodiert an `crypto.createPublicKey`.
- Die Tests erzeugen OpenSSH-Wire-Blobs direkt. Dadurch lassen sich ein zu kleiner RSA-Modulus, ein gerader RSA-Exponent und ein P-256-Punkt außerhalb der Kurve deterministisch prüfen.
- Ein positiver Security-Key-ECDSA-Test stellt sicher, dass `sk-ecdsa-sha2-nistp256@openssh.com` trotz strengerer Punktprüfung weiterhin akzeptiert wird.

## Testergebnisse

- `pnpm --filter create-paratix test` – bestanden, 146 Tests

## Review-Findings

**Datum:** 2026-05-04
**Reviewer:** sf-nodejs-reviewer

Keine Findings gefunden.
