# 0009 — net module

## Anforderung

Implementiere ein `net`-Modul für idempotente Netzwerkkonfiguration auf VPS-Systemen mit vier Methoden:

- `net.hosts()` — Verwaltet Einträge in `/etc/hosts`
- `net.interface()` — Konfiguriert Netzwerk-Interfaces via Netplan oder systemd-networkd
- `net.resolv()` — Verwaltet `/etc/resolv.conf` (Nameserver + Search-Domains)
- `net.route()` — Verwaltet persistente statische Routen

## API

```typescript
export const net = {
  hosts(ip: string, hostnames: string[], options?: { state?: "absent" | "present" }): Module
  interface(name: string, options: InterfaceOptions): Module
  resolv(options: { nameservers: string[]; search?: string[] }): Module
  route(destination: string, gateway: string, options?: { device?: string; state?: "absent" | "present" }): Module
}

type InterfaceOptions = {
  addresses?: string[]
  dhcp?: boolean
  gateway?: string
  nameservers?: string[]
}
```

## Architekturentscheidungen

### net.hosts()

- Zeilenbasierte Textmanipulation via `conn.readFile` / `conn.writeFile` auf `/etc/hosts`
- `state: "present"` (default): Prüft ob exakte Zeile `<ip> <hostname1> <hostname2>...` existiert. Fügt nur an wenn nicht vorhanden (Duplikat-Schutz). Gibt `status: "ok"` zurück wenn Eintrag bereits vorhanden.
- `state: "absent"`: Entfernt nur die exakte Zeile (nicht alle Einträge für die gleiche IP).

### net.resolv()

- Schreibt `/etc/resolv.conf` direkt. Entfernt vorher etwaigen Symlink von systemd-resolved (`rm -f`).
- Check vergleicht Dateiinhalt mit erwartetem Inhalt (`.trim()` auf beiden Seiten wegen `readFile`-Trimming).
- Generiert `nameserver`-Zeilen für jede IP und optionale `search`-Zeile.

### net.route()

- Check via `ip route show <destination>` — prüft ob Gateway im Output vorkommt.
- Apply via `ip route replace` (present) oder `ip route del` (absent).
- Persistenz: systemd-networkd `[Route]`-Drop-in unter `/etc/systemd/network/60-paratix-<device>.network.d/50-paratix-route-<sanitized-dest>-<route-hash>.conf`; `device` ist erforderlich, damit die Route nicht als eigenständige `.network`-Datei andere Interface-Konfigurationen verdrängt. Der Route-Hash enthält Destination, Gateway und Device, damit mehrere Routen zur gleichen Destination eindeutige Drop-in-Pfade erhalten.
- `sanitizeForFilename()` ersetzt `/` und `:` durch `-` für sichere Dateinamen (IPv4 + IPv6).

### net.interface()

- Auto-Detection: Prüft ob `/etc/netplan/` existiert → Netplan-Modus, sonst systemd-networkd.
- Netplan: Schreibt YAML nach `/etc/netplan/60-paratix-<name>.yaml`, dann `netplan apply`.
- systemd-networkd: Schreibt INI nach `/etc/systemd/network/60-paratix-<name>.network`, dann `networkctl reload`.
- Check vergleicht Dateiinhalt mit erwartetem Inhalt (`.trim()` auf beiden Seiten).

## Betroffene Dateien

| Datei                                       | Aktion                     |
| ------------------------------------------- | -------------------------- |
| `packages/paratix/src/modules/net.ts`       | Neu erstellt               |
| `packages/paratix/src/modules/index.ts`     | Export hinzugefügt         |
| `packages/paratix/test/modules/net.test.ts` | Neu erstellt               |
| `docs/module.md`                            | Dokumentation aktualisiert |

## Testergebnisse

68 Tests in 4 Kategorien:

- `net.hosts` — check (7 Tests) + apply (6 Tests)
- `net.resolv` — check (8 Tests) + apply (6 Tests)
- `net.route` — check (7 Tests) + apply (9 Tests)
- `net.interface` — check (12 Tests) + apply (13 Tests)

Alle 416 Projekt-Tests bestanden.

## Review-Findings und Behebung

| #   | Schweregrad | Finding                                                                                   | Behebung                                                                       |
| --- | ----------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| 1   | Kritisch    | `readFile()` trimmt trailing `\n`, `check()` von resolv/interface konnte nie "ok" liefern | `.trim()` Vergleich auf beiden Seiten                                          |
| 2   | Kritisch    | `hosts.apply()` fügte Duplikate hinzu (prüfte nicht ob Eintrag existiert)                 | Prüfung auf Existenz, `status: "ok"` bei Duplikat                              |
| 3   | Wichtig     | `hosts.apply()` bei "absent" löschte ALLE Einträge für die IP                             | Nur exakte Zeile entfernen (`line.trim() !== expectedLine`)                    |
| 4   | Wichtig     | Keine Input-Validierung für IP/Hostnames/Interface-Namen                                  | Akzeptiert — System-Boundary-Validierung ist Aufgabe des CLI, nicht der Module |
| 5   | Wichtig     | `resolv` deaktiviert systemd-resolved nicht                                               | Akzeptiert — Out-of-Scope, kann als separates Modul/Signal gelöst werden       |
| 6   | Hinweis     | `route.check()` prüft nur Laufzeit-Route, nicht Drop-in                                   | Akzeptiert — Route in Kernel ist die authoritative Quelle                      |
| 7   | Hinweis     | `sanitizeForFilename` erzeugt mehrfache Dashes bei IPv6                                   | Akzeptiert — funktional korrekt, kosmetisches Problem                          |
| 8   | Hinweis     | `env`-Parameter fehlt in Signaturen                                                       | Projekt-weites Muster, konsistent mit anderen Modulen                          |
