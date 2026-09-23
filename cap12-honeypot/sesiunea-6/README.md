# Honeypot: starea de la finalul sesiunii 6

**În carte:** capitolul 12, Aplicația practică 1, „Sesiunea 6”.

Clasificarea sesiunilor cu ML.NET. Este proiectul final, testat cap-coadă. Proiect complet; vezi `../README.md` pentru ce se adaugă în fiecare sesiune și pentru nota de etică.

```bash
docker compose up -d --build
docker build -t hp-attacker -f test/Dockerfile.client test
sh test/run-attacks.sh
docker exec honeypot-server dotnet Honeypot.dll classify
# sau, pe o copie adusă pe calculatorul vostru:
docker exec honeypot-server dotnet Honeypot.dll backup /data/snapshot.db
docker cp honeypot-server:/data/snapshot.db ./honeypot-copy.db
dotnet run -- classify honeypot-copy.db
```
