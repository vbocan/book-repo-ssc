# Aplicația practică 3: auditare cu trigger-e și tabele temporale (LabAudit)

**În carte:** capitolul 10, „Aplicații practice”, Aplicația practică 3.

Programul creează în baza `SQLInjectionLab` tabelele și trigger-ele de audit și un tabel temporal, simulează
activitate și detectează o modificare suspectă de preț (parsare cu `CultureInfo.InvariantCulture`).

**Cerințe:** baza `SQLInjectionLab` de la aplicația 1, serverul din `../compose.yaml`, .NET 10 SDK (Anexa A).
**Rulare:** `dotnet run`. Ieșirea așteptată este în carte (orele și utilizatorul curent diferă).
