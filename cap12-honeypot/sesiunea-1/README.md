# Honeypot: starea de la finalul sesiunii 1

**În carte:** capitolul 12, Aplicația practică 1, „Sesiunea 1”.

Server TCP multi-port și jurnalizare în SQLite. Proiect complet; vezi `../README.md` pentru ce se adaugă în fiecare sesiune și pentru nota de etică.

```bash
HONEYPOT_PORT_OFFSET=10000 dotnet run
```

## Rezultatul așteptat

Ieșirea serverului pentru testele din sesiunea 1 (clienții au rulat într-un alt container, cu adresa 172.20.0.3; la voi va apărea adresa gazdei văzută din container, iar orele diferă). Cartea tipărește doar liniile conexiunilor.

```
=== Honeypot Server v1.0 ===
Database: honeypot.db

[*] Listening on port 10021 (service 21)
[*] Listening on port 10022 (service 22)
[*] Listening on port 10023 (service 23)
[*] Listening on port 10080 (service 80)
[*] Listening on port 10443 (service 443)
[12:02:14] #1 172.20.0.3:57520 -> :22 | SSH-2.0-OpenSSH_10.0..
[12:02:15] #2 172.20.0.3:46797 -> :21 | USER admin..
[12:02:17] #3 172.20.0.3:58158 -> :80 | GET / HTTP/1.1..Host: hp-s1:10080..User-Agent: cur...
[12:02:17] #4 172.20.0.3:41376 -> :443 | ................
[12:02:18] #5 172.20.0.3:55150 -> :23 | root..
```
