# Aplicația practică 1: Reconstituirea cronologiei unui incident (IncidentTimeline)

**În carte:** capitolul 13, „Aplicații practice”, Aplicația practică 1.

Generează trei loguri demonstrative (web, autentificare, firewall) în directorul temporar, le parsează, le
normalizează la UTC și afișează cronologia unificată și tiparele suspecte.

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`.

Ieșirea este deterministă; cartea o tipărește scurtată, iar mai jos este ieșirea completă.

## Rezultatul așteptat

```
Generare loguri demonstrative...

[+] 7 evenimente din Firewall (firewall.log)
[+] 5 evenimente din WebServer (webserver.log)
[+] 6 evenimente din Auth (auth.log)

══════════════════════════════════════════════════════════════════════
 CRONOLOGIA INCIDENTULUI
══════════════════════════════════════════════════════════════════════
 Total evenimente: 18
 Interval: 2024-01-15 03:19:22Z — 2024-01-15 03:28:00Z
══════════════════════════════════════════════════════════════════════

 2024-01-15 03:19:22Z  [INF]  [WebServer   ] GET / → 200 (1234 bytes) user=-
                       Src: 10.0.1.45
 2024-01-15 03:20:01Z  [INF]  [Firewall    ] ALLOW TCP port 443
                       Src: 10.0.1.45  Dst: 203.0.113.50
 2024-01-15 03:20:15Z  [INF]  [Firewall    ] ALLOW TCP port 443
                       Src: 10.0.1.45  Dst: 203.0.113.50
 2024-01-15 03:21:05Z  [WRN]  [Auth        ] AUTH_FAILURE user=admin method=SSH
                       Src: 10.0.1.45
 2024-01-15 03:21:18Z  [WRN]  [Auth        ] AUTH_FAILURE user=admin method=SSH
                       Src: 10.0.1.45
 2024-01-15 03:21:35Z  [WRN]  [Auth        ] AUTH_FAILURE user=admin method=SSH
                       Src: 10.0.1.45
 2024-01-15 03:21:52Z  [WRN]  [Auth        ] AUTH_FAILURE user=admin method=SSH
                       Src: 10.0.1.45
 2024-01-15 03:22:08Z  [WRN]  [Auth        ] AUTH_FAILURE user=admin method=SSH
                       Src: 10.0.1.45
 2024-01-15 03:22:17Z  [WRN]  [Firewall    ] DENY TCP port 4444
                       Src: 10.0.1.45  Dst: 198.51.100.77
 2024-01-15 03:24:30Z  [INF]  [Auth        ] AUTH_SUCCESS user=admin method=SSH
                       Src: 10.0.1.45
 2024-01-15 03:24:51Z  [INF]  [WebServer   ] POST /admin/upload → 200 (4523 bytes) user=admin
                       Src: 10.0.1.45
 2024-01-15 03:24:55Z  [WRN]  [Firewall    ] DENY TCP port 4444
                       Src: 10.0.1.45  Dst: 198.51.100.77
 2024-01-15 03:25:03Z  [INF]  [WebServer   ] GET /admin/users → 200 (8901 bytes) user=admin
                       Src: 10.0.1.45
 2024-01-15 03:25:12Z  [WRN]  [Firewall    ] DENY TCP port 4444
                       Src: 10.0.1.45  Dst: 198.51.100.77
 2024-01-15 03:25:30Z  [INF]  [WebServer   ] GET /api/export/customers → 200 (245890 bytes) user=admin
                       Src: 10.0.1.45
 2024-01-15 03:26:15Z  [INF]  [WebServer   ] DELETE /admin/logs → 200 (45 bytes) user=admin
                       Src: 10.0.1.45
 2024-01-15 03:26:30Z  [INF]  [Firewall    ] ALLOW TCP port 443
                       Src: 10.0.1.45  Dst: 203.0.113.50
 2024-01-15 03:28:00Z  [WRN]  [Firewall    ] DENY TCP port 8080
                       Src: 10.0.1.45  Dst: 198.51.100.77

══════════════════════════════════════════════════════════════════════
 TIPARE SUSPECTE DETECTATE
══════════════════════════════════════════════════════════════════════

 [BRUTE FORCE] IP: 10.0.1.45
   5 eșecuri în 3.4 min, urmate de autentificare reușită
   Prima încercare: 2024-01-15 03:21:05Z
   Autentificare reușită: 2024-01-15 03:24:30Z

 [ACCES SENSIBIL] 4 accesări la resurse administrative/sensibile:
   2024-01-15 03:24:51Z  POST /admin/upload → 200 (4523 bytes) user=admin
   2024-01-15 03:25:03Z  GET /admin/users → 200 (8901 bytes) user=admin
   2024-01-15 03:25:30Z  GET /api/export/customers → 200 (245890 bytes) user=admin
   2024-01-15 03:26:15Z  DELETE /admin/logs → 200 (45 bytes) user=admin

 [C2 / BEACONING?] 4 conexiuni blocate către 198.51.100.77 (porturi: 4444, 8080)
   Interval: 2024-01-15 03:22:17Z — 2024-01-15 03:28:00Z
```
