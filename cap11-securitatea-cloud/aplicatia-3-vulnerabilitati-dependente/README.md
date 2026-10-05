# Aplicația practică 3: Verificator de vulnerabilități pentru dependențe (VulnCheck)

**În carte:** capitolul 11, „Aplicații practice”, Aplicația practică 3.

Compară inventarul unei imagini de container cu o bază de vulnerabilități **inventate** (`DEMO-2026-0101`…`0107`) și
întoarce un cod de ieșire nenul când găsește vulnerabilități critice, ca într-un pipeline CI.
**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`, apoi `echo $?` (bash) sau `$LASTEXITCODE` (PowerShell): 1.
Cartea tipărește doar prima vulnerabilitate și sumarul; ieșirea completă este mai jos (data scanării va fi cea a rulării voastre).

## Rezultatul așteptat

```
═══════════════════════════════════════════════════
   RAPORT VULNERABILITĂȚI CONTAINER
   Imagine: myapp:1.2.3-alpine
   Data scanării: 2026-09-23 09:28 UTC
═══════════════════════════════════════════════════

[CRITIC ] DEMO-2026-0106 (CVSS: 9.8)
  Pachet:    libdemossl v3.0.7 (alpine-apk)
  Descriere: Scriere în afara limitelor la parsarea unui certificat X.509, cu execuție de cod la distanță.
  Corecție:  actualizați la versiunea 3.0.10

[RIDICAT] DEMO-2026-0101 (CVSS: 8.7)
  Pachet:    Contoso.Data.Client v4.8.3 (nuget)
  Descriere: Canalul TLS către server poate fi retrogradat (downgrade), permițând interceptarea datelor.
  Corecție:  actualizați la versiunea 4.8.6

[RIDICAT] DEMO-2026-0102 (CVSS: 7.5)
  Pachet:    Contoso.Web.Server v7.0.5 (nuget)
  Descriere: Negarea serviciului prin deschiderea și anularea rapidă a fluxurilor HTTP/2.
  Corecție:  actualizați la versiunea 7.0.12

[RIDICAT] DEMO-2026-0107 (CVSS: 7.4)
  Pachet:    libdemossl v3.0.7 (alpine-apk)
  Descriere: Confuzie de tip la compararea numelor din certificat, cu citire de memorie sau DoS.
  Corecție:  actualizați la versiunea 3.0.8

[MEDIU  ] DEMO-2026-0104 (CVSS: 6.8)
  Pachet:    Contoso.Identity.Tokens v6.32.0 (nuget)
  Descriere: Negarea serviciului printr-un token criptat și comprimat care se decomprimă la dimensiuni uriașe.
  Corecție:  actualizați la versiunea 7.1.2

[MEDIU  ] DEMO-2026-0103 (CVSS: 6.5)
  Pachet:    Contoso.Crypto.X509 v7.0.2 (nuget)
  Descriere: Consum excesiv de procesor la validarea unui lanț de certificate construit special.
  Corecție:  actualizați la versiunea 7.0.11

═══════════════════════════════════════════════════
Total vulnerabilități: 6
  Critice:  1
  Ridicate: 3
  Medii:    2

DECIZIE: BLOCAT. Imaginea conține vulnerabilități critice și nu trebuie implementată.
```
