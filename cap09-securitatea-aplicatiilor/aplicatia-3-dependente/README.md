# Aplicația practică 3: scanarea vulnerabilităților din dependențe

**În carte:** capitolul 9, „Aplicații practice”, Aplicația practică 3.

| Proiect | Pasul | Ce face |
|---|---|---|
| `LabScanner/` | 1 | Scaner didactic: citește `PackageReference` dintr-un `.csproj` și le compară cu o bază de vulnerabilități **fictive** (`DEMO-2026-0001`…`0005`, pachete Contoso/Fabrikam/Northwind inventate) |
| `vulnerabil/AuditDemo/` | 2 | Proiect cu `Newtonsoft.Json` **12.0.3**, versiune reală afectată de CVE-2024-21907, pentru NuGet Audit |

> ⚠️ **Cod intenționat vulnerabil.** Folosiți-l doar pe calculatorul vostru, legat de `127.0.0.1`, pentru a înțelege atacul. Nu îl publicați pe internet și nu îl copiați în aplicații reale.

**Rulare:**

```bash
cd LabScanner && dotnet run
cd ../vulnerabil/AuditDemo
dotnet restore
dotnet list package --vulnerable --include-transitive
```

La `dotnet restore`, proiectul `AuditDemo` afișează intenționat avertismentul `NU1903`. Actualizați apoi pachetul
(`dotnet add package Newtonsoft.Json`) și repetați comanda: lista trebuie să fie goală. Cartea tipărește ieșirea scanerului prescurtată; ieșirile complete sunt mai jos
(pe un sistem cu setări regionale românești, scorurile CVSS apar cu virgulă).

## Rezultatul așteptat

Scanerul (`LabScanner`, `dotnet run`):

```
=== SCANNER VULNERABILITĂȚI DEPENDENȚE ===

Dependențe identificate în .csproj:
  • Contoso.Json v4.2.0
  • Contoso.Logging v2.5.1
  • Fabrikam.Data v3.1.0
  • Fabrikam.Imaging v1.8.0
  • Northwind.Mapping v7.0.0
  • Northwind.Validation v5.4.2

╔══════════════════════════════════════════════════╗
║    RAPORT SCANARE VULNERABILITĂȚI DEPENDENȚE     ║
╚══════════════════════════════════════════════════╝

Total dependențe scanate: 6
Vulnerabilități identificate: 4

Sumar severitate:
  [!!!] Critice:  1
  [!!]  Ridicate: 1
  [!]   Medii:    2

[!!!] DEMO-2026-0002: Fabrikam.Data v3.1.0
    Severitate: Critică (CVSS 9.8)
    Descriere:  Execuție de cod la distanță prin șiruri de conexiune manipulate
    Remediere:  actualizați la 3.1.5 sau mai nou

[!!] DEMO-2026-0001: Contoso.Json v4.2.0
    Severitate: Ridicată (CVSS 8.1)
    Descriere:  Deserializare nesigură când este activată rezolvarea tipurilor din JSON
    Remediere:  actualizați la 4.2.3 sau mai nou

[!] DEMO-2026-0003: Contoso.Logging v2.5.1
    Severitate: Medie (CVSS 5.3)
    Descriere:  Log injection: caracterele de linie nouă nu sunt neutralizate
    Remediere:  actualizați la 2.6.0 sau mai nou

[!] DEMO-2026-0004: Northwind.Mapping v7.0.0
    Severitate: Medie (CVSS 4.3)
    Descriere:  Mass assignment: proprietăți nemapate explicit sunt copiate implicit
    Remediere:  actualizați la 7.0.1 sau mai nou

Dependențe fără vulnerabilități în baza de date:
  [OK] Fabrikam.Imaging v1.8.0
  [OK] Northwind.Validation v5.4.2

ACȚIUNE IMEDIATĂ: există vulnerabilități critice care trebuie remediate înainte de deployment.
```

NuGet Audit (`vulnerabil/AuditDemo`, `dotnet list package --vulnerable --include-transitive`):

```
Project `AuditDemo` has the following vulnerable packages
   [net10.0]:
   Top-level Package      Requested   Resolved   Severity   Advisory URL
   > Newtonsoft.Json      12.0.3      12.0.3     High       https://github.com/advisories/GHSA-5crp-9r3c-p9vr
```
