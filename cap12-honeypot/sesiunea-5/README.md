# Honeypot: starea de la finalul sesiunii 5

**În carte:** capitolul 12, Aplicația practică 1, „Sesiunea 5”.

Analiza datelor colectate. Proiect complet; vezi `../README.md` pentru ce se adaugă în fiecare sesiune și pentru nota de etică.

```bash
docker compose up -d --build
docker build -t hp-attacker -f test/Dockerfile.client test
sh test/run-attacks.sh
docker exec honeypot-server dotnet Honeypot.dll analyze
# sau, pe o copie adusă pe calculatorul vostru:
docker exec honeypot-server dotnet Honeypot.dll backup /data/snapshot.db
docker cp honeypot-server:/data/snapshot.db ./honeypot-copy.db
dotnet run -- analyze honeypot-copy.db
```

## Rezultatul așteptat

Raportul `analyze` complet pe traficul de test generat cu `test/run-attacks.sh`. Cartea tipărește doar secțiunile de detecție (brute force, scanări, campanii). Valorile pot diferi de la o rulare la alta: ferestrele de 5 minute sunt aliniate la ceas, iar o sesiune care traversează granița dintre două ferestre se împarte în două grupuri.

```
════════════════════════════════════════════════════════
  HONEYPOT ANALYSIS REPORT
════════════════════════════════════════════════════════

── Connections by port ──
  SSH       22 │     26 │ ██████████████████████████████
  FTP       21 │      9 │ ██████████
  HTTP      80 │      5 │ █████
  Telnet    23 │      5 │ █████
  HTTPS    443 │      2 │ ██

── Top source IPs ──
  172.30.0.102           25  private
  172.30.0.104            5  private
  172.30.0.103            5  private
  172.30.0.109            4  private
  172.30.0.101            4  private
  172.30.0.108            1  private
  172.30.0.107            1  private
  172.30.0.106            1  private
  172.30.0.105            1  private

── Hourly distribution (UTC) ──
  12:00 │     47 │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

── Top credentials (FTP, Telnet, HTTP) ──
  FTP          admin        admin               4
  Telnet       admin        admin               4
  Telnet       root         vizxv               4
  Telnet       root         xc3511              4
  FTP          admin        1234                1
  FTP          admin        123456              1
  FTP          admin        12345678            1
  FTP          admin        P@ssw0rd            1
  FTP          admin        admin123            1
  FTP          admin        changeme            1

── SSH clients (identification string) ──
  SSH-2.0-OpenSSH_10.0                         25

── Brute force ──
  172.30.0.101          4 connections,   15 credentials in 23s
  172.30.0.109          4 connections,   12 credentials in 31s
  172.30.0.102         25 connections,    0 credentials in 24s

── Port scans ──
  172.30.0.103       5 ports in 0.1s
  172.30.0.104       3 ports in 0.2s

── Credential campaigns (same pair, >= 3 IPs) ──
  admin:admin from 6 IPs, 9 attempts
════════════════════════════════════════════════════════
```
