// ============================================================
// Program principal
// ============================================================

// Dependențele extrase (simulat) dintr-o imagine de container.
// Toate pachetele și vulnerabilitățile din acest exercițiu sunt FICTIVE.
var dependenteContainer = new List<Dependenta>
{
    new("Contoso.Data.Client", "4.8.3", "nuget"),
    new("Contoso.Web.Server", "7.0.5", "nuget"),
    new("Contoso.Crypto.X509", "7.0.2", "nuget"),
    new("Contoso.Identity.Tokens", "6.32.0", "nuget"),
    new("Contoso.Json", "13.0.3", "nuget"),
    new("libdemossl", "3.0.7", "alpine-apk"),
    new("libdemoz", "1.3.1", "alpine-apk"),
    new("Contoso.Logging", "3.1.1", "nuget")
};

var scanner = new VulnerabilityScanner();
var rezultate = scanner.Scaneaza(dependenteContainer);

RaportGenerator.GenereazaRaportConsola(rezultate, "myapp:1.2.3-alpine");

// Cod de ieșire pentru pipeline-ul CI: 1 dacă există vulnerabilități critice
Environment.ExitCode = rezultate.Any(r =>
    r.Vulnerabilitate.Severitate == SeveritateVuln.Critica) ? 1 : 0;

// ============================================================
// Modelul de date pentru vulnerabilități
// ============================================================

public enum SeveritateVuln { Neglijabila, Scazuta, Medie, Ridicata, Critica }

public record Vulnerabilitate(
    string Id,
    string Pachet,
    string VersiuneAfectataMin,
    string VersiuneAfectataMax,
    string VersiuneCorectata,
    SeveritateVuln Severitate,
    double ScorCVSS,
    string Descriere
);

public record Dependenta(
    string Nume,
    string Versiune,
    string Ecosistem  // "nuget", "npm", "alpine-apk" etc.
);

public record RezultatScanare(
    Dependenta Dependenta,
    Vulnerabilitate Vulnerabilitate,
    bool AreCorectie
);

// ============================================================
// Baza de date simulată. Identificatorii DEMO-2026-xxxx și
// pachetele Contoso.* / libdemo* sunt INVENTATE: nu căutați
// aceste ID-uri în NVD. Scanerele reale folosesc ID-uri CVE,
// GHSA sau ale distribuțiilor.
// ============================================================

public static class BazaDateVulnerabilitati
{
    public static List<Vulnerabilitate> Obtine() =>
    [
        new(Id: "DEMO-2026-0101",
            Pachet: "Contoso.Data.Client",
            VersiuneAfectataMin: "1.0.0",
            VersiuneAfectataMax: "4.8.5",
            VersiuneCorectata: "4.8.6",
            Severitate: SeveritateVuln.Ridicata,
            ScorCVSS: 8.7,
            Descriere: "Canalul TLS către server poate fi retrogradat " +
                       "(downgrade), permițând interceptarea datelor."),
        new(Id: "DEMO-2026-0102",
            Pachet: "Contoso.Web.Server",
            VersiuneAfectataMin: "6.0.0",
            VersiuneAfectataMax: "7.0.11",
            VersiuneCorectata: "7.0.12",
            Severitate: SeveritateVuln.Ridicata,
            ScorCVSS: 7.5,
            Descriere: "Negarea serviciului prin deschiderea și anularea " +
                       "rapidă a fluxurilor HTTP/2."),
        new(Id: "DEMO-2026-0103",
            Pachet: "Contoso.Crypto.X509",
            VersiuneAfectataMin: "6.0.0",
            VersiuneAfectataMax: "7.0.10",
            VersiuneCorectata: "7.0.11",
            Severitate: SeveritateVuln.Medie,
            ScorCVSS: 6.5,
            Descriere: "Consum excesiv de procesor la validarea unui " +
                       "lanț de certificate construit special."),
        new(Id: "DEMO-2026-0104",
            Pachet: "Contoso.Identity.Tokens",
            VersiuneAfectataMin: "5.0.0",
            VersiuneAfectataMax: "7.1.1",
            VersiuneCorectata: "7.1.2",
            Severitate: SeveritateVuln.Medie,
            ScorCVSS: 6.8,
            Descriere: "Negarea serviciului printr-un token criptat și " +
                       "comprimat care se decomprimă la dimensiuni uriașe."),
        new(Id: "DEMO-2026-0105",
            Pachet: "Contoso.Json",
            VersiuneAfectataMin: "1.0.0",
            VersiuneAfectataMax: "13.0.0",
            VersiuneCorectata: "13.0.1",
            Severitate: SeveritateVuln.Ridicata,
            ScorCVSS: 7.5,
            Descriere: "Depășire de stivă la deserializarea unui JSON " +
                       "cu imbricare foarte adâncă."),
        new(Id: "DEMO-2026-0106",
            Pachet: "libdemossl",
            VersiuneAfectataMin: "3.0.0",
            VersiuneAfectataMax: "3.0.9",
            VersiuneCorectata: "3.0.10",
            Severitate: SeveritateVuln.Critica,
            ScorCVSS: 9.8,
            Descriere: "Scriere în afara limitelor la parsarea unui " +
                       "certificat X.509, cu execuție de cod la distanță."),
        new(Id: "DEMO-2026-0107",
            Pachet: "libdemossl",
            VersiuneAfectataMin: "3.0.0",
            VersiuneAfectataMax: "3.0.7",
            VersiuneCorectata: "3.0.8",
            Severitate: SeveritateVuln.Ridicata,
            ScorCVSS: 7.4,
            Descriere: "Confuzie de tip la compararea numelor din " +
                       "certificat, cu citire de memorie sau DoS.")
    ];
}

// ============================================================
// Scanerul de vulnerabilități
// ============================================================

public class VulnerabilityScanner
{
    private readonly List<Vulnerabilitate> _bazaDate =
        BazaDateVulnerabilitati.Obtine();

    public List<RezultatScanare> Scaneaza(List<Dependenta> dependente)
    {
        var rezultate = new List<RezultatScanare>();

        foreach (var dep in dependente)
        {
            // Căutăm vulnerabilitățile pentru acest pachet și versiune
            var potriviri = _bazaDate
                .Where(v => string.Equals(v.Pachet, dep.Nume,
                    StringComparison.OrdinalIgnoreCase))
                .Where(v => EsteVersiuneAfectata(
                    dep.Versiune, v.VersiuneAfectataMin,
                    v.VersiuneAfectataMax));

            foreach (var v in potriviri)
            {
                rezultate.Add(new RezultatScanare(
                    Dependenta: dep,
                    Vulnerabilitate: v,
                    AreCorectie: !string.IsNullOrEmpty(v.VersiuneCorectata)));
            }
        }

        return [.. rezultate
            .OrderByDescending(r => r.Vulnerabilitate.Severitate)
            .ThenByDescending(r => r.Vulnerabilitate.ScorCVSS)];
    }

    // LIMITARE: comparația liniară min ≤ v ≤ max presupune o singură
    // ramură de versiuni. Pentru pachete cu mai multe ramuri întreținute
    // în paralel (ex: 1.1.x și 3.0.x) ar fi nevoie de mai multe intervale.
    private static bool EsteVersiuneAfectata(
        string versiuneInstalata, string versiuneMin, string versiuneMax)
    {
        if (!TryParseVersiune(versiuneInstalata, out var instalata) ||
            !TryParseVersiune(versiuneMin, out var min) ||
            !TryParseVersiune(versiuneMax, out var max))
        {
            // Dacă nu putem compara, raportăm pachetul ca posibil afectat
            return true;
        }
        return instalata >= min && instalata <= max;
    }

    private static bool TryParseVersiune(string text, out Version versiune)
    {
        // „1.2.3-preview” sau „3.0.7-r0” (apk): păstrăm partea numerică
        var curat = text.Split('-')[0];
        return Version.TryParse(curat, out versiune!);
    }
}

// ============================================================
// Generatorul de rapoarte
// ============================================================

public static class RaportGenerator
{
    public static void GenereazaRaportConsola(
        List<RezultatScanare> rezultate, string numeImagine)
    {
        Console.WriteLine("═══════════════════════════════════════════════════");
        Console.WriteLine("   RAPORT VULNERABILITĂȚI CONTAINER");
        Console.WriteLine($"   Imagine: {numeImagine}");
        Console.WriteLine($"   Data scanării: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC");
        Console.WriteLine("═══════════════════════════════════════════════════");
        Console.WriteLine();

        if (rezultate.Count == 0)
        {
            Console.WriteLine("  Nu au fost identificate vulnerabilități cunoscute.");
            return;
        }

        foreach (var r in rezultate)
        {
            string indicator = r.Vulnerabilitate.Severitate switch
            {
                SeveritateVuln.Critica => "CRITIC ",
                SeveritateVuln.Ridicata => "RIDICAT",
                SeveritateVuln.Medie => "MEDIU  ",
                SeveritateVuln.Scazuta => "SCAZUT ",
                _ => "INFO   "
            };

            Console.WriteLine($"[{indicator}] {r.Vulnerabilitate.Id} " +
                $"(CVSS: {r.Vulnerabilitate.ScorCVSS.ToString("F1",
                    System.Globalization.CultureInfo.InvariantCulture)})");
            Console.WriteLine($"  Pachet:    {r.Dependenta.Nume} " +
                $"v{r.Dependenta.Versiune} ({r.Dependenta.Ecosistem})");
            Console.WriteLine($"  Descriere: {r.Vulnerabilitate.Descriere}");
            Console.WriteLine(r.AreCorectie
                ? $"  Corecție:  actualizați la versiunea " +
                  $"{r.Vulnerabilitate.VersiuneCorectata}"
                : "  Corecție:  nu există încă o versiune corectată; " +
                  "evaluați alternative.");
            Console.WriteLine();
        }

        // Sumar
        Console.WriteLine("═══════════════════════════════════════════════════");
        Console.WriteLine($"Total vulnerabilități: {rezultate.Count}");
        Console.WriteLine($"  Critice:  {rezultate.Count(r =>
            r.Vulnerabilitate.Severitate == SeveritateVuln.Critica)}");
        Console.WriteLine($"  Ridicate: {rezultate.Count(r =>
            r.Vulnerabilitate.Severitate == SeveritateVuln.Ridicata)}");
        Console.WriteLine($"  Medii:    {rezultate.Count(r =>
            r.Vulnerabilitate.Severitate == SeveritateVuln.Medie)}");

        // Decizia pentru pipeline
        Console.WriteLine();
        if (rezultate.Any(r =>
                r.Vulnerabilitate.Severitate == SeveritateVuln.Critica))
            Console.WriteLine("DECIZIE: BLOCAT. Imaginea conține " +
                "vulnerabilități critice și nu trebuie implementată.");
        else if (rezultate.Any(r =>
                r.Vulnerabilitate.Severitate == SeveritateVuln.Ridicata))
            Console.WriteLine("DECIZIE: ATENȚIE. Vulnerabilitățile ridicate " +
                "trebuie remediate înainte de implementare.");
        else
            Console.WriteLine("DECIZIE: ACCEPTABIL. Nicio vulnerabilitate " +
                "critică sau ridicată.");
    }
}
