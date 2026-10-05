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

## Rezultatul așteptat

Ieșirea completă a comenzii `dotnet run -- classify honeypot-copy.db` pe traficul de test. Antrenarea și evaluarea dau aceleași valori la fiecare rulare; tabelul sesiunilor depinde de traficul vostru. Cartea tipărește doar o parte din tabelul sesiunilor.

```
Training attack classifier...

Test set: 150 sessions
  Macro accuracy: 100.00 %
  Micro accuracy: 100.00 %
  Log loss:       0.0267

  Class            Precision  Recall     F1
  BruteForce           1.000   1.000  1.000
  PortScan             1.000   1.000  1.000
  Reconnaissance       1.000   1.000  1.000
  ResearchScanner      1.000   1.000  1.000

  Confusion matrix (rows = actual, columns = predicted):
                    Brute  PortS  Recon  Resea
  BruteForce           30      0      0      0
  PortScan              0     46      0      0
  Reconnaissance        0      0     35      0
  ResearchScanner       0      0      0     39

Classifying 9 sessions (IP x hour):

  Source IP       Conn/min Ports  Bytes Creds  Dur(s)  Prediction
  172.30.0.103         5.0     5      0     0     0.2  PortScan
  172.30.0.104         5.0     3     98     2     0.2  PortScan
  172.30.0.105         1.0     1    110     0     0.0  ResearchScanner
  172.30.0.109         4.0     1     29    12    40.6  BruteForce
  172.30.0.101         4.0     1     80    15    24.5  BruteForce
  172.30.0.102        25.0     1    430     0    24.2  BruteForce
  172.30.0.106         1.0     1     24     1     2.6  ResearchScanner
  172.30.0.107         1.0     1     24     1     2.6  ResearchScanner
  172.30.0.108         1.0     1     24     1     2.6  ResearchScanner

Summary:
  ResearchScanner    4 sessions
  BruteForce         3 sessions
  PortScan           2 sessions
```
