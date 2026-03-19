# ADR-0002: Defer broad integration matrix expansion

**Status:** Accepted
**Datum:** 2026-03-19
**Kontext:** /build-feature — Review-Finding R-001 zu breiterer Modulintegrationsmatrix

## Kontext

Der Review-Bericht `review-report-2026-03-19.md` enthält mit R-001 ein wichtiges Finding:
Die reale Server-Abdeckung in `packages/paratix/test/integration/paratix.integration.test.ts`
ist bewusst schmal und deckt aktuell nur SSH-Basisverhalten sowie die Modulfamilien `file`,
`command` und `download` gegen einen echten Host ab. Ein großer Teil der öffentlichen
Moduloberfläche bleibt weiterhin mock-validiert.

Im aktuellen Ausbau der Integrationsstrategie wurden bereits ein verlässlicher
Integrationspfad (`agent:check:integration`) sowie zusätzliche echte Server-Szenarien
für die bestehenden Schwerpunktbereiche umgesetzt. Die weitergehende Forderung aus R-001,
auch Module wie `apt/package`, `service/systemd`, `cron`, `sshd`, `net`, `mount`,
`user/group`, `git` oder `rsync` in die echte Integrationsmatrix aufzunehmen, würde den
Scope deutlich erweitern.

## Entscheidung

R-001 wird vorläufig nicht umgesetzt. Die reale Integrationsmatrix bleibt zunächst bewusst
auf SSH-Basisverhalten sowie `file`, `command` und `download` beschränkt.

## Begründung

- **Bewusste Scope-Begrenzung:** Der aktuelle Integrationspfad sollte zuerst stabil,
  reproduzierbar und im Review einsetzbar werden. Eine breite Modulintegrationsmatrix
  hätte den Scope des letzten Ausbaus deutlich überschritten.
- **Hoher Infrastrukturaufwand:** Viele der in R-001 genannten Module benötigen für
  belastbare E2E-Tests zusätzliche Systemdienste, Netzwerk-Setup oder zustandsbehaftete
  OS-Umgebung. Das würde den Testcontainer und die Testlogik erheblich komplexer machen.
- **Fragilitätsrisiko:** Eine schnelle Ausweitung auf zahlreiche stark OS-gebundene Module
  würde die Integrationssuite langsamer und störanfälliger machen, bevor der aktuelle
  Kernpfad ausreichend lange stabil im Einsatz war.
- **Priorisierung:** Die bisher priorisierten echten Pfade (`file`, `command`, `download`,
  SSH/SFTP/Reconnect) adressieren bereits zentrale Risiken rund um Shell-Quoting,
  Dateizustand, Transfers und reale Host-Kommunikation.
- **Follow-up statt Verwerfen:** Das Finding bleibt fachlich gültig. Es wird nicht
  negiert, sondern bewusst als späteres Follow-up zurückgestellt.

## Quelle

- **Finding:** R-001 — Reale Server-Abdeckung endet bei 4 Modulfamilien, der Rest ist weiter nur mock-validiert
- **Schweregrad:** Wichtig
- **Dateien:** review-report-2026-03-19.md, packages/paratix/test/integration/paratix.integration.test.ts
