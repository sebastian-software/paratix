# 0022 — rsync StrictHostKeyChecking konfigurierbar machen

## Anforderung

Der rsync-SSH-Transport verwendet hartcodiertes `StrictHostKeyChecking=no`. Default auf `accept-new` aendern und als Konfigurationsoption in `SyncOptions` anbieten.

## Architekturentscheidungen

- **Platzierung der Option:** In `SyncOptions` (lokal in `rsync.ts`), nicht in `SshConfig` (`types.ts`). Begruendung: Nur das rsync-Modul baut den SSH-Transport-String; andere Module nutzen `ssh2` direkt. Minimaler Blast-Radius.
- **Typ:** Union-Type `"accept-new" | "no" | "off" | "yes"` statt `string`. Begruendung: Der Wert wird in einen SSH-Befehlsstring interpoliert. Ein offener `string`-Typ wuerde Injection-Vektoren eroeffnen. Union-Type bietet Compile-Time-Sicherheit und IDE-Autovervollstaendigung.
- **Default:** `"accept-new"` via Nullish-Coalescing (`??`). Bietet TOFU-Semantik (Trust On First Use), die fuer IaC-Ersteinrichtung sinnvoll ist, waehrend geaenderte Host-Keys weiterhin abgelehnt werden.

## Betroffene Dateien

| Datei                                         | Aenderung                                                                |
| --------------------------------------------- | ------------------------------------------------------------------------ |
| `packages/paratix/src/modules/rsync.ts`       | `SyncOptions` erweitert, Default geaendert, JSDoc aktualisiert           |
| `packages/paratix/test/modules/rsync.test.ts` | Bestehender Test auf `accept-new` angepasst, neuer Test fuer Custom-Wert |

## Implementierungsdetails

### `SyncOptions` (rsync.ts:26-34)

Neue Property mit JSDoc:

```typescript
strictHostKeyChecking?: "accept-new" | "no" | "off" | "yes"
```

### SSH-Transport-String (rsync.ts:113)

```typescript
;`ssh -p ${connectionInfo.port} -i "${connectionInfo.privateKeyPath}" -o StrictHostKeyChecking=${options.strictHostKeyChecking ?? "accept-new"}`
```

### Tests (rsync.test.ts)

1. Bestehender Test aktualisiert: Prueft auf `StrictHostKeyChecking=accept-new` (neuer Default)
2. Neuer Test: Prueft dass `strictHostKeyChecking: "no"` korrekt durchgereicht wird
3. Neuer Test: Prueft dass `strictHostKeyChecking: "yes"` korrekt als `-o StrictHostKeyChecking=yes` im SSH-Transport-String landet

## Testergebnisse

- 799/799 Tests bestanden
- TypeScript: 0 Fehler
- Linting (oxlint + ESLint): 0 Fehler, 0 Warnungen
- Prettier: alle Dateien formatiert

## Review-Findings

| ID    | Schweregrad | Bereich    | Status  | Beschreibung                                                                             |
| ----- | ----------- | ---------- | ------- | ---------------------------------------------------------------------------------------- |
| R-001 | Kritisch    | Security   | Behoben | `string`-Typ erlaubte Injection via SSH-Transport-String. Auf Union-Type eingeschraenkt. |
| R-002 | Wichtig     | API Design | Behoben | Zusammen mit R-001 durch Union-Type geloest.                                             |
| R-003 | Hinweis     | Tests      | Behoben | Test fuer `"yes"`-Wert ergaenzt.                                                         |
