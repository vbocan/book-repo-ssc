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

Cartea tipărește o ieșire prescurtată (fără lista comenzilor văzute de administrator); ieșirea completă este mai jos.

## Rezultatul așteptat

```
=== Test Row-Level Security ===

--- Conectat ca: Departament IT ---
  [1] Licențe Visual Studio       15,000.00 RON  (IT)
  [2] Servere rack                45,000.00 RON  (IT)
  [5] Switch-uri rețea            22,000.00 RON  (IT)
  Total: 3 comenzi vizibile
  INSERT în departamentul HR: BLOCAT de block predicate (RLS)

--- Conectat ca: Departament HR ---
  [3] Training management          8,000.00 RON  (HR)
  [4] Echipamente birou           12,000.00 RON  (HR)
  [6] Cursuri limba engleză        5,000.00 RON  (HR)
  Total: 3 comenzi vizibile

--- Conectat ca: Administrator ---
  [1] Licențe Visual Studio       15,000.00 RON  (IT)
  [2] Servere rack                45,000.00 RON  (IT)
  [3] Training management          8,000.00 RON  (HR)
  [4] Echipamente birou           12,000.00 RON  (HR)
  [5] Switch-uri rețea            22,000.00 RON  (IT)
  [6] Cursuri limba engleză        5,000.00 RON  (HR)
  Total: 6 comenzi vizibile
```
