# Capitolul 12: Construirea unui honeypot în șase sesiuni

**În carte:** capitolul 12, „Aplicații practice”, Aplicația practică 1.

> ⚠️ **Etică și lege.** Un honeypot expus pe internet se rulează doar pe infrastructura voastră (o instanță cloud
> dedicată, fără alte date), izolat cum descrie sesiunea 4, cu egress blocat. Accesul neautorizat rămâne infracțiune și
> când ținta este un honeypot (în România, art. 360 din Codul penal), iar voi nu aveți dreptul să „ripostați”.
> Adresele IP colectate sunt date cu caracter personal (GDPR, cauza C-582/14 *Breyer*): păstrați-le limitat și securizat
> (secțiunea 12.4, „Limitele legale și etice”).

Fiecare director `sesiunea-N/` este un proiect **complet**, în starea de la finalul sesiunii N; dacă ați rămas în
urmă, porniți de la instantaneul sesiunii anterioare. `sesiunea-6/` este proiectul final testat.

| Director | Ce se adaugă față de sesiunea anterioară |
|---|---|
| `sesiunea-1/` | `HoneypotDatabase.cs` (SQLite, interogări parametrizate), `HoneypotServer.cs` (listener multi-port, `ConsoleSafe`), `Program.cs` |
| `sesiunea-2/` | `ServiceEmulators.cs` (FTP, SSH, Telnet, HTTP/HTTPS), tabelele `InteractionLog` și `CredentialLog`, noul `HandleClientAsync` |
| `sesiunea-3/` | `Dockerfile`, `.dockerignore`, `docker-compose.yml` (codul C# este cel din sesiunea 2) |
| `sesiunea-4/` | `HealthCheck.cs`, `BasicStats` și `BackupTo`, subcomenzile `serve` și `backup`, `docker-compose.prod.yml`, `monitor-honeypot.sh`, `backup-honeypot.sh`, `crontab.txt` |
| `sesiunea-5/` | `HoneypotAnalyzer.cs`, subcomanda `analyze`, generatorul de trafic de test din `test/` |
| `sesiunea-6/` | `AttackClassifier.cs` (ML.NET), subcomanda `classify`, pachetul `Microsoft.ML` |

**Cerințe:** .NET 10 SDK (Anexa A); Docker (Anexa C) din sesiunea 3; pentru sesiunea 4, o instanță cloud proprie.

**Rulare locală (sesiunile 1–2)**, fără drepturi de administrator, cu porturile deplasate cu 10000:

```bash
cd sesiunea-2
HONEYPOT_PORT_OFFSET=10000 dotnet run        # PowerShell: $env:HONEYPOT_PORT_OFFSET=10000; dotnet run
```

**În container (sesiunile 3–6):**

```bash
cd sesiunea-6
docker compose up -d --build
curl http://127.0.0.1:9090/                  # health check (din sesiunea 4)
docker exec honeypot-server dotnet Honeypot.dll analyze
docker compose down                          # datele rămân în volumul honeypot-data
```

În sesiunea 3 containerul apare „unhealthy”: `HEALTHCHECK` folosește endpoint-ul scris abia în sesiunea 4, cum
explică și cartea. Traficul de test din sesiunea 5 se generează cu `test/run-attacks.sh` (vezi cartea), rulat dintr-un
shell Linux, macOS sau WSL: scriptul montează `$PWD/test` în containere, iar în Git Bash pe Windows această cale nu
ajunge corect la Docker. Numărătorile din raportul `analyze` pot diferi ușor de la o rulare la alta (ferestrele de
5 minute sunt aliniate la ceas, deci o sesiune poate fi împărțită între două ferestre).
Cartea tipărește din ieșirea fiecărei sesiuni doar liniile care arată fenomenul discutat; ieșirile complete se află în secțiunea „Rezultatul așteptat” din README-ul fiecărui director `sesiunea-N/`.
