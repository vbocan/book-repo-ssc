# Aplicația practică 2: Row-Level Security (LabRls)

**În carte:** capitolul 10, „Aplicații practice”, Aplicația practică 2.

`setup-rls.sql` creează login-urile SQL `UserIT`, `UserHR` și `UserAdmin`, tabelul `ComenziDepartamentale` și politica de securitate cu
filter și block predicate (`AFTER INSERT` și `AFTER UPDATE`). Programul se conectează cu trei identități diferite și
arată ce vede fiecare și că inserarea în alt departament este blocată.

**Cerințe:** baza `SQLInjectionLab` de la aplicația 1 (rulați întâi `../aplicatia-1-sql-injection/setup.sql`),
serverul din `../compose.yaml`, .NET 10 SDK (Anexa A).

**Rulare**, din directorul capitolului:

```bash
docker compose cp aplicatia-2-row-level-security/setup-rls.sql sqlserver:/tmp/rls.sql
docker compose exec sqlserver sh -c \
  '/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -i /tmp/rls.sql'
cd aplicatia-2-row-level-security
dotnet run
```

Ieșirea așteptată este în carte.
