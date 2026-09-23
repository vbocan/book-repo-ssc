using System.Xml.Linq;

// Un fișier .csproj de test. Pachetele Contoso.*, Fabrikam.* și Northwind.* sunt
// FICTIVE, la fel ca vulnerabilitățile din baza de date de mai jos.
string csprojContent = """
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Contoso.Json" Version="4.2.0" />
    <PackageReference Include="Contoso.Logging" Version="2.5.1" />
    <PackageReference Include="Fabrikam.Data" Version="3.1.0" />
    <PackageReference Include="Fabrikam.Imaging" Version="1.8.0" />
    <PackageReference Include="Northwind.Mapping" Version="7.0.0" />
    <PackageReference Include="Northwind.Validation" Version="5.4.2" />
  </ItemGroup>
</Project>
""";

var scanner = new ScannerDependente();

Console.WriteLine("=== SCANNER VULNERABILITĂȚI DEPENDENȚE ===\n");

var dependente = scanner.ExtrageDependente(csprojContent);
Console.WriteLine("Dependențe identificate în .csproj:");
foreach (var (pachet, versiune) in dependente)
    Console.WriteLine($"  • {pachet} v{versiune}");
Console.WriteLine();

var vulnerabilitati = scanner.Scaneaza(dependente);
scanner.GenereazaRaport(dependente, vulnerabilitati);

// ---------------------------------------------------------------------------
// Tipuri (declarate DUPĂ instrucțiunile top-level, altfel apare eroarea CS8803)
// ---------------------------------------------------------------------------

public record Vulnerabilitate(
    string Id,
    string PachetAfectat,
    string VersiuneMinAfectata,
    string VersiuneMaxAfectata,
    double ScorCvss,
    string Severitate,
    string Descriere,
    string VersiuneCorectata);

public class ScannerDependente
{
    // Bază de date SIMULATĂ, cu identificatori fictivi (DEMO-...). În practică,
    // datele vin din GitHub Advisory Database, OSV sau NVD.
    private readonly List<Vulnerabilitate> _bazaDeDate =
    [
        new("DEMO-2026-0001", "Contoso.Json", "4.0.0", "4.2.2", 8.1, "Ridicată",
            "Deserializare nesigură când este activată rezolvarea tipurilor din JSON",
            "4.2.3"),
        new("DEMO-2026-0002", "Fabrikam.Data", "3.0.0", "3.1.4", 9.8, "Critică",
            "Execuție de cod la distanță prin șiruri de conexiune manipulate",
            "3.1.5"),
        new("DEMO-2026-0003", "Contoso.Logging", "2.0.0", "2.5.3", 5.3, "Medie",
            "Log injection: caracterele de linie nouă nu sunt neutralizate",
            "2.6.0"),
        new("DEMO-2026-0004", "Northwind.Mapping", "6.0.0", "7.0.0", 4.3, "Medie",
            "Mass assignment: proprietăți nemapate explicit sunt copiate implicit",
            "7.0.1"),
        new("DEMO-2026-0005", "Fabrikam.Imaging", "1.0.0", "1.5.9", 7.5, "Ridicată",
            "Denial of service la procesarea imaginilor malformate",
            "1.6.0"),
    ];

    // Parsarea fișierului .csproj pentru extragerea elementelor PackageReference
    public List<(string Pachet, string Versiune)> ExtrageDependente(string csprojContent)
    {
        var dependente = new List<(string Pachet, string Versiune)>();
        try
        {
            var doc = XDocument.Parse(csprojContent);
            foreach (var pkg in doc.Descendants("PackageReference"))
            {
                string? pachet = pkg.Attribute("Include")?.Value;
                string? versiune = pkg.Attribute("Version")?.Value
                    ?? pkg.Element("Version")?.Value;
                if (!string.IsNullOrEmpty(pachet) && !string.IsNullOrEmpty(versiune))
                    dependente.Add((pachet, versiune));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Eroare la parsarea .csproj: {ex.Message}");
        }
        return dependente;
    }

    // Compararea versiunilor (simplificată: doar major.minor.patch, fără sufixe -beta etc.)
    private static bool EsteVersiuneAfectata(string versiune, string min, string max)
    {
        if (!Version.TryParse(versiune, out var ver) ||
            !Version.TryParse(min, out var vMin) ||
            !Version.TryParse(max, out var vMax))
            return false; // format nerecunoscut
        return ver >= vMin && ver <= vMax;
    }

    public List<(string Pachet, string Versiune, Vulnerabilitate Vuln)> Scaneaza(
        List<(string Pachet, string Versiune)> dependente)
    {
        var rezultate = new List<(string Pachet, string Versiune, Vulnerabilitate Vuln)>();
        foreach (var (pachet, versiune) in dependente)
            foreach (var vuln in _bazaDeDate)
                if (string.Equals(pachet, vuln.PachetAfectat, StringComparison.OrdinalIgnoreCase)
                    && EsteVersiuneAfectata(versiune, vuln.VersiuneMinAfectata, vuln.VersiuneMaxAfectata))
                    rezultate.Add((pachet, versiune, vuln));

        return rezultate.OrderByDescending(r => r.Vuln.ScorCvss).ToList();
    }

    public void GenereazaRaport(
        List<(string Pachet, string Versiune)> dependente,
        List<(string Pachet, string Versiune, Vulnerabilitate Vuln)> vulnerabilitati)
    {
        Console.WriteLine("╔══════════════════════════════════════════════════╗");
        Console.WriteLine("║    RAPORT SCANARE VULNERABILITĂȚI DEPENDENȚE     ║");
        Console.WriteLine("╚══════════════════════════════════════════════════╝\n");

        Console.WriteLine($"Total dependențe scanate: {dependente.Count}");
        Console.WriteLine($"Vulnerabilități identificate: {vulnerabilitati.Count}\n");

        int critice = vulnerabilitati.Count(v => v.Vuln.Severitate == "Critică");
        int ridicate = vulnerabilitati.Count(v => v.Vuln.Severitate == "Ridicată");
        int medii = vulnerabilitati.Count(v => v.Vuln.Severitate == "Medie");

        Console.WriteLine("Sumar severitate:");
        if (critice > 0) Console.WriteLine($"  [!!!] Critice:  {critice}");
        if (ridicate > 0) Console.WriteLine($"  [!!]  Ridicate: {ridicate}");
        if (medii > 0) Console.WriteLine($"  [!]   Medii:    {medii}");
        Console.WriteLine();

        foreach (var (pachet, versiune, vuln) in vulnerabilitati)
        {
            string indicator = vuln.Severitate switch
            {
                "Critică" => "[!!!]",
                "Ridicată" => "[!!]",
                _ => "[!]"
            };
            Console.WriteLine($"{indicator} {vuln.Id}: {pachet} v{versiune}");
            Console.WriteLine($"    Severitate: {vuln.Severitate} (CVSS {vuln.ScorCvss:0.0})");
            Console.WriteLine($"    Descriere:  {vuln.Descriere}");
            Console.WriteLine($"    Remediere:  actualizați la {vuln.VersiuneCorectata} sau mai nou");
            Console.WriteLine();
        }

        var pacheteVulnerabile = vulnerabilitati
            .Select(v => v.Pachet).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var pacheteFaraProbleme = dependente
            .Where(d => !pacheteVulnerabile.Contains(d.Pachet)).ToList();

        if (pacheteFaraProbleme.Count > 0)
        {
            Console.WriteLine("Dependențe fără vulnerabilități în baza de date:");
            foreach (var (pachet, versiune) in pacheteFaraProbleme)
                Console.WriteLine($"  [OK] {pachet} v{versiune}");
            Console.WriteLine();
        }

        if (critice > 0)
            Console.WriteLine("ACȚIUNE IMEDIATĂ: există vulnerabilități critice care " +
                "trebuie remediate înainte de deployment.");
        else if (ridicate > 0)
            Console.WriteLine("ATENȚIE: vulnerabilități cu severitate ridicată; " +
                "planificați remedierea în sprintul curent.");
        else if (medii > 0)
            Console.WriteLine("INFORMARE: vulnerabilități cu severitate medie; " +
                "includeți remedierea în backlog.");
        else
            Console.WriteLine("Nicio vulnerabilitate cunoscută în dependențele scanate.");
    }
}
