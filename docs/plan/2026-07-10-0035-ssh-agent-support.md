# 0035 — SSH Agent Support

## Anforderung

SSH-Agent als Alternative zum direkten Private-Key-Loading implementieren. Wenn ein
SSH-Agent verfuegbar ist, diesen nutzen statt den Key direkt zu laden. Fallback auf
direktes Key-Loading wenn kein Agent verfuegbar. Optionales Agent-Forwarding zum
Remote-Host.

## Architekturentscheidungen

- **Auto-Detect statt explizites Feld:** Kein neues `agent`-Feld in `SshConfig`.
  Wenn `privateKey` fehlt, wird automatisch `SSH_AUTH_SOCK` aus der Umgebung
  gelesen. Das haelt die Playbook-Config minimal.
- **SSH_AUTH_SOCK zur Connect-Zeit:** Der Agent-Socket wird in `connect()` gelesen,
  nicht beim Config-Parsing. So funktionieren Playbooks auch in CI-Umgebungen wo
  der Agent erst spaeter verfuegbar ist.
- **Agent-Forwarding:** Neues optionales `agentForward?: boolean` Feld in
  `SshConfig`, wird direkt an ssh2 `ConnectConfig.agentForward` durchgereicht.
- **Rueckwaertskompatibilitaet:** `privateKey` bleibt nutzbar, ist aber jetzt
  optional. Alle bestehenden Playbooks funktionieren unveraendert.

## Betroffene Dateien

| Datei                  | Aenderung                                                                                                  |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| `src/types.ts`         | `SshConfig.privateKey` optional, `agentForward?: boolean` neu, `getConnectionInfo.privateKeyPath` optional |
| `src/ssh.ts`           | `connect()` mit zwei Pfaden (Key vs. Agent), `tryConnectOnPorts` mit agent-Parameter                       |
| `src/sshHelpers.ts`    | `ConnectParameters` um `agent?`/`agentForward?` erweitert, `tryConnectOnPort` baut connectConfig bedingt   |
| `src/server.ts`        | Validation: `privateKey` nur bei gesetztem Wert geprueft                                                   |
| `src/cli.ts`           | `collectSshErrors`: `privateKey` nur required wenn vorhanden                                               |
| `src/modules/rsync.ts` | `buildArguments` akzeptiert optionales `privateKeyPath`                                                    |
| `llm-guide.md`         | SSH-Beispiel und Dokumentation aktualisiert                                                                |
| `test/ssh.test.ts`     | 6 neue Agent-Auth-Tests                                                                                    |
| `test/cli.test.ts`     | Angepasst (2 statt 3 Fehler bei fehlenden SSH-Subfeldern)                                                  |

## Testergebnisse

- 1034 Tests bestanden (vorher 1009), 0 fehlgeschlagen
- 0 TypeScript-Fehler, 0 Lint-Fehler
- Neue Tests: Agent-Auth erfolgreich, fehlendes SSH_AUTH_SOCK, leeres
  SSH_AUTH_SOCK, alle Ports fehlgeschlagen, agentForward-Weiterleitung,
  Key-Auth-Rueckwaertskompatibilitaet

## Review-Findings

| #     | Schweregrad | Status | Beschreibung                                              |
| ----- | ----------- | ------ | --------------------------------------------------------- |
| R-001 | Wichtig     | Offen  | Rsync: kein expliziter Agent-Socket-Pfad im SSH-Transport |
| R-002 | Hinweis     | Offen  | passwordFallback nicht im Agent-Auth-Pfad                 |
| R-003 | Hinweis     | Offen  | Agent-Socket-Pfad keine Existenzpruefung                  |
| R-004 | Hinweis     | Offen  | connectConfig: Record statt ssh2.ConnectConfig            |
