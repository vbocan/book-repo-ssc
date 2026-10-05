# Aplicația practică 1: Scanner de securitate IoT pe un laborator simulat

**În carte:** capitolul 16, „Aplicații practice”, Aplicația practică 1.

> ⚠️ `laborator-iot/docker-compose.yml` pornește servicii **intenționat nesigure** (Telnet, panou web cu `admin:admin`,
> broker MQTT anonim), toate legate doar de `127.0.0.1`. Nu le expuneți în rețea. `ScannerIoT` refuză implicit orice
> adresă care nu este locală; scanarea unor sisteme fără autorizare scrisă este ilegală (capitolul 15, Codul penal art. 360–366).

**Cerințe:** Docker (Anexa C), .NET 10 SDK (Anexa A).

**Rulare:**

```bash
cd laborator-iot && docker compose up -d && docker compose ps
cd ../ScannerIoT && dotnet run
cd ../laborator-iot && docker compose down
```

Cartea tipărește ieșirea scannerului scurtată (doar constatările celor două brokere); mai jos este ieșirea completă. Remedierea de la pasul 4 se face în `docker-compose.yml`.

## Rezultatul așteptat

Cu laboratorul pornit, `dotnet run` din `ScannerIoT/` afișează:

```
=== SCANNER SECURITATE IoT ===
Țintă: 127.0.0.1, dispozitive: 5

[SCAN] 127.0.0.1:2323 (Telnet) ... port deschis
[SCAN] 127.0.0.1:8080 (HTTP) ... port deschis
[SCAN] 127.0.0.1:1883 (MQTT) ... port deschis
[SCAN] 127.0.0.1:1884 (MQTT) ... port deschis
[SCAN] 127.0.0.1:2201 (SSH) ... port închis

============================================================
RAPORT SECURITATE IoT
============================================================
  [CRITIC]        2
  [RIDICAT]       4
  [MEDIU]         1
  [SCĂZUT]        1
  [DE VERIFICAT]  2

>>> 127.0.0.1:2323
  [RIDICAT]       Telnet activ, credențialele circulă în clar
                  dovadă: negociere Telnet (IAC), 35 octeți
  [DE VERIFICAT]  Credențialele implicite Telnet nu au fost testate
                  dovadă: testați manual, cu autorizare, cele 6 perechi din listă

>>> 127.0.0.1:8080
  [CRITIC]        Credențiale implicite acceptate
                  dovadă: HTTP Basic admin:admin -> 200
  [RIDICAT]       Panou de administrare prin HTTP, fără TLS
                  dovadă: GET http://127.0.0.1:8080/ -> 401
  [MEDIU]         Header-e de securitate lipsă
                  dovadă: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
  [SCĂZUT]        Versiunea serverului este expusă
                  dovadă: Server: nginx/1.30.5

>>> 127.0.0.1:1883
  [CRITIC]        Brokerul acceptă clienți anonimi
                  dovadă: CONNACK cod 0 (acceptat) fără credențiale
  [RIDICAT]       MQTT fără TLS, mesajele și parolele circulă în clar
                  dovadă: brokerul a răspuns la CONNECT pe un port necriptat

>>> 127.0.0.1:1884
  [RIDICAT]       MQTT fără TLS, mesajele și parolele circulă în clar
                  dovadă: brokerul a răspuns la CONNECT pe un port necriptat
  [DE VERIFICAT]  Brokerul refuză clienții anonimi
                  dovadă: CONNACK cod 5 (5 = neautorizat); verificați ACL-urile pe topic-uri
```
