# Honeypot: starea de la finalul sesiunii 4

**În carte:** capitolul 12, Aplicația practică 1, „Sesiunea 4”.

Deployment în cloud, health check, monitorizare și backup. Proiect complet; vezi `../README.md` pentru ce se adaugă în fiecare sesiune și pentru nota de etică.

```bash
docker compose up -d --build
curl http://127.0.0.1:9090/
```

## Rezultatul așteptat

Răspunsul health check-ului (`curl http://127.0.0.1:9090/`) pe un volum nou; după testele din sesiunea 3 veți vedea numărul acestora. Cartea doar enumeră câmpurile.

```
Status: OK
Uptime: 0d 00:00
TotalConnections: 0
LastHour: 0
Last24h: 0
DBSize: 0.0 MB
```
