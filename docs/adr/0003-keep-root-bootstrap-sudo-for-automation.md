# 0003 — Root-Bootstrap-Sudo bleibt für Automation erhalten

## Status

Nicht umgesetzt

## Kontext

Review-Report: `.sf-plugin/review/review-report-2026-05-05-2.md`, Finding R-0000324
Workflow: $sf-apply-review

## Entscheidung

Die von Root-Bootstrap-Projekten erzeugte `NOPASSWD:ALL`-Sudo-Regel wird vorerst beibehalten, weil Paratix weiterhin automatische Root-Berechtigung für bestimmte geplante Aufgaben benötigt.

## Begründung

Die Entwickler-Anmerkung zum Finding lautet: Das ist „on purpose", da Paratix weiterhin automatische Root-Berechtigung braucht für bestimmte TODOs. Bitte in ADR dokumentieren. Falls das anders gelöst werden kann, bitte genauer beschreiben.

Eine alternative Lösung sollte erst entworfen werden, wenn klar ist, welche Root-Operationen nach dem Bootstrap dauerhaft automatisiert werden müssen und welche davon auf konkrete Kommandos oder einen späteren Cleanup-Schritt begrenzt werden können.

## Quell-Finding

R-0000324 aus `.sf-plugin/review/review-report-2026-05-05-2.md`: Root-Bootstrap-Projekte erzeugen dauerhaft eine sudoers-Datei mit `NOPASSWD:ALL` für den Admin-User. Nach dem Bootstrap gibt es keinen generierten Cleanup und keine Begrenzung auf konkrete Befehle. Eine Kompromittierung des Admin-SSH-Keys führt damit direkt zu vollständigem Root-Zugriff ohne weitere Hürde.
