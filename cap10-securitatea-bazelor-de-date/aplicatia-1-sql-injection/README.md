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

Ieșirea așteptată este în carte. Rulați `setup.sql` din nou înainte de a repeta programul (migrarea golește coloana `Parola`).
