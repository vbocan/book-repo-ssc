# Capitolul 10: Securitatea bazelor de date

**În carte:** capitolul 10 (secțiunile 10.1–10.5 și „Aplicații practice”) și Anexa C.6.

## Serverul de laborator

Toate scripturile și programele folosesc **SQL Server 2025 Developer** în container, pornit cu `compose.yaml`
(Anexa C.6). Portul este legat doar de `127.0.0.1`, iar parola contului `sa` se citește din `.env`, care nu se
adaugă în Git:

```bash
cp .env.example .env               # parola din Pasul 0: Parola_Lab_2026!
docker compose up -d --wait
docker compose exec sqlserver sh -c \
  '/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -Q "SELECT @@VERSION"'
```

Programele din aplicațiile practice au parola `Parola_Lab_2026!` scrisă în connection string, ca în carte;
dacă o schimbați în `.env`, schimbați-o și acolo. Imaginea există doar pentru x64 (pe Apple Silicon rulează prin emulare).

Rularea unui script `.sql` în container (din acest director):

```bash
docker compose cp sql/10-2-row-level-security.sql sqlserver:/tmp/s.sql
docker compose exec sqlserver sh -c \
  '/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -i /tmp/s.sql'
```

În Git Bash pe Windows, puneți `MSYS_NO_PATHCONV=1` în fața comenzilor `docker compose exec`, altfel calea
`/opt/mssql-tools18/...` este transformată într-o cale Windows.

**De ce `127.0.0.1` și nu `localhost`.** Pe Windows, cu `localhost` conexiunea eșuează (eroarea *Named Pipes Provider,
error: 40*): numele se rezolvă întâi la adresa IPv6 `::1`, pe care Docker nu publică portul (este legat doar de `127.0.0.1`), iar clientul
SqlClient trece apoi la Named Pipes. De aceea programele folosesc `Server=127.0.0.1,1433`
(în LabRls: `DataSource = "127.0.0.1,1433"`); nu reveniți la `localhost`.

La final: `docker compose down -v` (șterge și volumul cu datele).

## Conținut

| Director | Ce conține |
|---|---|
| `sql/` | Scripturile T-SQL din secțiunile 10.1–10.5, câte unul pentru fiecare exemplu, rulabile singure |
| `sql/vulnerabil/` | Exemplul `xp_cmdshell` (10.1) și payload-urile de SQL injection analizate în 10.5 |
| `aplicatia-1-sql-injection/` | Laboratorul de SQL injection: `setup.sql` și programul `vulnerabil/` (LabInjection) |
| `aplicatia-2-row-level-security/` | `setup-rls.sql` și programul LabRls (trei utilizatori, trei vederi asupra datelor) |
| `aplicatia-3-audit/` | Programul LabAudit: trigger-e de audit, tabel temporal, detectarea unei modificări de preț |
| `exemple/` | Programele C# din 10.3 (Always Encrypted, criptarea în tranzit) și clasele din 10.1 și 10.5 |

Fiecare script din `sql/` are trei părți marcate: pregătirea (obiectele pe care exemplul din carte le presupune,
de exemplu tabelele și utilizatorii), codul din carte, neschimbat, și o verificare. Scripturile recreează baza
`SSCCap10` la fiecare rulare. Excepții: `10-3-tde.sql` creează chei în `master` și se rulează o singură dată pe un
container proaspăt; `10-5-sql-server-audit.sql` își dezactivează la final auditul (care are `ON_FAILURE = SHUTDOWN`).
