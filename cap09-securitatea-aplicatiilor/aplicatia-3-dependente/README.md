# Aplicația practică 3: scanarea vulnerabilităților din dependențe

**În carte:** capitolul 9, „Aplicații practice”, Aplicația practică 3.

| Proiect | Pasul | Ce face |
|---|---|---|
| `LabScanner/` | 1–2 | Scaner didactic: citește `PackageReference` dintr-un `.csproj` și le compară cu o bază de vulnerabilități **fictive** (`DEMO-2026-0001`…`0005`, pachete Contoso/Fabrikam/Northwind inventate) |
| `vulnerabil/AuditDemo/` | 3 | Proiect cu `Newtonsoft.Json` **12.0.3**, versiune reală afectată de CVE-2024-21907, pentru NuGet Audit |

> ⚠️ **Cod intenționat vulnerabil.** Folosiți-l doar pe calculatorul vostru, legat de `127.0.0.1`, pentru a înțelege atacul. Nu îl publicați pe internet și nu îl copiați în aplicații reale.

**Rulare:**

```bash
cd LabScanner && dotnet run
cd ../vulnerabil/AuditDemo
dotnet list package --vulnerable --include-transitive
```

Build-ul lui `AuditDemo` afișează intenționat avertismentul `NU1903`. Actualizați apoi pachetul
(`dotnet add package Newtonsoft.Json`) și repetați comanda: lista trebuie să fie goală. Ieșirile așteptate sunt în carte
(pe un sistem cu setări regionale românești, scorurile CVSS apar cu virgulă).
