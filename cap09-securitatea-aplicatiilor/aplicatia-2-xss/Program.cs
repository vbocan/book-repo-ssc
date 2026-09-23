using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Ganss.Xss;

// Payload-uri XSS cunoscute, plus un input legitim
var payloads = new (string Descriere, string Payload)[]
{
    ("Script simplu", "<script>alert('XSS')</script>"),
    ("Event handler pe imagine", "<img src=x onerror=alert('XSS')>"),
    ("JavaScript în href", "<a href=\"javascript:alert('XSS')\">Click</a>"),
    ("SVG cu onload", "<svg onload=alert('XSS')>"),
    ("Tag neînchis", "<img src=x onerror=alert(1) "),
    ("Tag-uri imbricate", "<<script>alert('XSS')//<</script>"),
    ("Tag-uri permise și nepermise",
        "<b>Text bold</b><script>alert('XSS')</script><i>italic</i>"),
    ("Input legitim", "O <b>recenzie</b> pentru <i>produsul</i> comandat."),
};

// Biblioteca HtmlSanitizer (pachetul NuGet „HtmlSanitizer”, namespace Ganss.Xss):
// parsează HTML-ul ca un browser și păstrează doar ce este în lista albă.
var sanitizer = new HtmlSanitizer();
sanitizer.AllowedTags.Clear();
foreach (var tag in new[] { "b", "i", "u", "em", "strong", "p", "br", "ul", "ol", "li" })
    sanitizer.AllowedTags.Add(tag);
sanitizer.AllowedAttributes.Clear();   // niciun atribut, deci niciun on*=, href, style

Console.WriteLine("=== TESTARE SANITIZARE XSS ===\n");

foreach (var (descriere, payload) in payloads)
{
    Console.WriteLine($"Test: {descriere}");
    Console.WriteLine($"  Input:         {payload}");
    var amenintari = XssDemo.DetecteazaXss(payload);
    Console.WriteLine($"  Detectat:      {(amenintari.Count > 0 ? string.Join(", ", amenintari) : "nimic")}");
    Console.WriteLine($"  Codificat:     {XssDemo.CodificareCompleta(payload)}");
    Console.WriteLine($"  Regex (naiv):  {XssDemo.SanitizeazaCuRegex(payload)}");
    Console.WriteLine($"  HtmlSanitizer: {sanitizer.Sanitize(payload)}");
    Console.WriteLine();
}

// ATENȚIE: clasa de mai jos este DIDACTICĂ. Filtrarea HTML cu expresii regulate
// NU este sigură în producție (vezi testul „Tag neînchis”). Folosiți codificarea
// ieșirii sau o bibliotecă de sanitizare verificată, precum HtmlSanitizer.
static class XssDemo
{
    private static readonly HashSet<string> TaguriPermise = new(StringComparer.OrdinalIgnoreCase)
    {
        "b", "i", "u", "em", "strong", "p", "br", "ul", "ol", "li"
    };

    private static readonly (string Nume, Regex Pattern)[] TiparePericuloase =
    {
        ("script", new Regex(@"<script[\s>]", RegexOptions.IgnoreCase)),
        ("event handler", new Regex(@"\bon\w+\s*=", RegexOptions.IgnoreCase)),
        ("javascript:", new Regex(@"javascript\s*:", RegexOptions.IgnoreCase)),
        ("iframe/object", new Regex(@"<(iframe|object|embed)[\s>]", RegexOptions.IgnoreCase)),
    };

    // Metoda 1: codificare HTML completă (cea mai sigură când nu trebuie păstrat HTML)
    public static string CodificareCompleta(string input) =>
        string.IsNullOrEmpty(input) ? string.Empty : HtmlEncoder.Default.Encode(input);

    // Metoda 2: filtru regex cu listă albă de tag-uri (NAIV, doar pentru comparație)
    public static string SanitizeazaCuRegex(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        return Regex.Replace(input, @"</?(\w+)([^>]*)>", match =>
        {
            string tag = match.Groups[1].Value;
            bool esteInchidere = match.Value.StartsWith("</");
            if (!TaguriPermise.Contains(tag))
                return string.Empty;                   // eliminăm tag-ul nepermis
            return esteInchidere ? $"</{tag}>" : $"<{tag}>"; // eliminăm toate atributele
        });
    }

    // Detectarea unor tipare frecvente (utilă pentru jurnalizare, NU ca apărare)
    public static List<string> DetecteazaXss(string input)
    {
        var amenintari = new List<string>();
        foreach (var (nume, pattern) in TiparePericuloase)
            if (pattern.IsMatch(input))
                amenintari.Add(nume);
        return amenintari;
    }
}
