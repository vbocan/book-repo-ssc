# Aplicația practică 1: laboratorul de SQL injection

**În carte:** capitolul 10, „Aplicații practice”, Pas 0 și Aplicația practică 1.

> ⚠️ **Cod intenționat vulnerabil.** Folosiți-l doar pe calculatorul vostru, legat de `127.0.0.1`, pentru a înțelege atacul. Nu îl publicați pe internet și nu îl copiați în aplicații reale.

- `setup.sql` creează baza `SQLInjectionLab` cu tabelele `Utilizatori` (parole **în clar**, intenționat, ca să vedeți
  ce expune atacul) și `Produse`.
- `vulnerabil/` (LabInjection) conține funcțiile vulnerabile (concatenare), migrarea parolelor la PBKDF2 și
  funcțiile securizate (interogări parametrizate), apoi rulează demonstrațiile: bypass cu `admin'--`, exfiltrare
  prin `UNION`, remedierea.

**Cerințe:** serverul din `../compose.yaml` (vezi `../README.md`), .NET 10 SDK (Anexa A).

**Rulare**, din directorul capitolului:

```bash
docker compose cp aplicatia-1-sql-injection/setup.sql sqlserver:/tmp/setup.sql
docker compose exec sqlserver sh -c \
  '/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -i /tmp/setup.sql'
cd aplicatia-1-sql-injection/vulnerabil
dotnet run
```

Cartea tipărește o ieșire prescurtată; ieșirea completă este mai jos. Rulați `setup.sql` din nou înainte de a repeta programul (migrarea golește coloana `Parola`).

## Rezultatul așteptat

Rulat pe SQL Server 2025; ordinea produselor poate diferi ușor.

```
=== SQL Injection Lab ===

--- Atac 1: bypass autentificare (aplicația vulnerabilă) ---
Input: username = admin' --, parola = orice

  SQL generat: SELECT Username, Rol FROM Utilizatori WHERE Username = 'admin' --' AND Parola = 'orice'
  Autentificat ca: admin (rol: administrator)
  Rezultat: ACCES PERMIS

--- Atac 2: exfiltrare prin UNION (căutare de produse vulnerabilă) ---
Input: ' UNION SELECT NULL, Username + ':' + Parola, NULL, NULL FROM Utilizatori --

  SQL generat: SELECT Denumire, Descriere, Pret, Stoc FROM Produse WHERE Denumire LIKE '%' UNION SELECT NULL, Username + ':' + Parola, NULL, NULL FROM Utilizatori --%'
   | admin:SuperSecretAdmin!
   | ionescu:Parola123
   | popescu:Test456!
   | vasilescu:Secure789
  Laptop Dell XPS 15 | Laptop ultraperformant
  Monitor LG 27" | Monitor 4K IPS
  Mouse wireless | Senzor 25000 DPI
  Tastatură mecanică | Switch-uri Cherry MX

=== Remediere ===
Pas A: migrarea parolelor la hash
  4 parole migrate la PBKDF2; coloana Parola golită.

Pas B: aceleași atacuri contra codului securizat
[Login securizat] username = admin' --, parola = orice
  Rezultat: acces refuzat
[Login securizat] username = admin, parola corectă
  Autentificat ca: admin (rol: administrator)
  Rezultat: ACCES PERMIS
[Căutare securizată] cu payload UNION:
  0 produse găsite (input tratat ca dată)
```
