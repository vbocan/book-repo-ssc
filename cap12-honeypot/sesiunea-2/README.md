# Honeypot: starea de la finalul sesiunii 2

**În carte:** capitolul 12, Aplicația practică 1, „Sesiunea 2”.

Emularea serviciilor FTP, SSH, Telnet, HTTP și HTTPS. Proiect complet; vezi `../README.md` pentru ce se adaugă în fiecare sesiune și pentru nota de etică.

```bash
HONEYPOT_PORT_OFFSET=10000 dotnet run
```

## Rezultatul așteptat

Ieșirea serverului pentru testele din sesiunea 2 (adrese și ore din rularea noastră). Cartea tipărește doar liniile SSH, FTP și Telnet.

```
[12:02:53] #1 172.20.0.3:34308 -> :22
  [SSH] Client: SSH-2.0-OpenSSH_10.0
  [SSH] KEXINIT hassh=eeca2460550b9ded084ecf2f70a75356
[12:02:53] #2 172.20.0.3:34207 -> :21
  [FTP] Credential attempt: admin:admin123
[12:02:56] #3 172.20.0.3:39090 -> :80
  [HTTP] <- GET / HTTP/1.1
[12:02:56] #4 172.20.0.3:44342 -> :443
  [HTTPS] <- GET / HTTP/1.1
[12:02:56] #5 172.20.0.3:41124 -> :23
  [Telnet] Credential attempt: root:123456
```
