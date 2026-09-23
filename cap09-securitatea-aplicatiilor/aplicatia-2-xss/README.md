# Aplicația practică 2: codificarea ieșirii și sanitizarea HTML contra XSS (LabXss)

**În carte:** capitolul 9, „Aplicații practice”, Aplicația practică 2.

Compară codificarea HTML a ieșirii (`HtmlEncoder`), un filtru regex **naiv**,
păstrat intenționat doar pentru comparație, și sanitizarea cu `HtmlSanitizer` (pachetul mganss, 9.2.1039).

**Cerințe:** .NET 10 SDK (Anexa A), acces la nuget.org. **Rulare:** `dotnet run`. Ieșirea este deterministă și coincide cu cea din carte.
