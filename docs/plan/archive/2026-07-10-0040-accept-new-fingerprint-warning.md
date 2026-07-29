# 0040 — Accept-New Host Key Fingerprint Warning

## Anforderung

Wenn `strictHostKeyChecking` auf `accept-new` steht und ein neuer Host-Key akzeptiert wird, soll eine sichtbare Warnung mit dem Key-Fingerprint ausgegeben werden.

## Architekturentscheidungen

- **Fingerprint-Format:** SHA256 Base64 ohne Padding (OpenSSH-kompatibel, wie `ssh-keygen -l`)
- **Output-Kanal:** `process.stderr.write` — bestehendes Pattern für Warnings im Projekt
- **Error Handling:** try/catch um den Warning-Block, damit ein korrupter Key-Buffer die Verbindung nicht verhindert. Im Fehlerfall wird eine vereinfachte Warnung ohne Fingerprint ausgegeben.

## Betroffene Dateien

| Datei                                      | Änderung                                                           |
| ------------------------------------------ | ------------------------------------------------------------------ |
| `packages/paratix/src/knownHosts.ts`       | Neue Funktion `computeFingerprint`, Warning in `buildHostVerifier` |
| `packages/paratix/test/knownHosts.test.ts` | 5 neue Tests (4 für `computeFingerprint`, 1 für Warning-Output)    |

## Implementierungsdetails

### `computeFingerprint(key: Buffer): string`

Berechnet `SHA256:<base64-hash>` aus dem Key-Buffer via `node:crypto`. Trailing `=` Padding wird entfernt, um dem OpenSSH-Format zu entsprechen.

### Warning in `buildHostVerifier`

Im `accept-new`-Pfad wird vor dem fire-and-forget `appendHostKey` eine synchrone Warnung auf stderr geschrieben:

```
WARNING: Permanently added 'hostname' (ssh-ed25519) to the list of known hosts. Fingerprint: SHA256:xxxxx
```

Der Block ist in try/catch gewrapped, damit die Verbindung auch bei Problemen mit der Fingerprint-Berechnung nicht abbricht.

## Testergebnisse

- 1163 Tests bestanden (43 in `knownHosts.test.ts`)
- Lint: 0 Errors
- TypeScript: 0 Errors
- Format: bestanden

## Review-Findings

| ID    | Schweregrad | Bereich        | Status     |
| ----- | ----------- | -------------- | ---------- |
| R-001 | Wichtig     | Error Handling | ✅ Behoben |
| R-002 | Hinweis     | Test Coverage  | ✅ Behoben |

- **R-001:** try/catch um Warning-Block hinzugefügt, damit korrupter Key-Buffer die Verbindung nicht crasht.
- **R-002:** Test mit echtem 4096-bit RSA Public Key und ssh-keygen-verifiziertem Fingerprint hinzugefügt.
