using System.Globalization;
using System.Text.RegularExpressions;

// ============================================================
// Reconstituirea cronologiei unui incident din loguri multiple
// ============================================================

// ------------------------------------------------------------
// Programul principal (instrucțiunile de nivel superior trebuie
// să preceadă declarațiile de tipuri, altfel apare eroarea CS8803)
// ------------------------------------------------------------

var logDir = Path.Combine(
    Path.GetTempPath(), "incident-timeline-demo");

Console.WriteLine("Generare loguri demonstrative...\n");
GenerateSampleLogs(logDir);

var builder = new IncidentTimelineBuilder();
builder.RegisterParser(new FirewallLogParser());
builder.RegisterParser(new WebServerLogParser());
builder.RegisterParser(new AuthLogParser());

builder.LoadLogs(new Dictionary<string, string>
{
    ["Firewall"]  = Path.Combine(logDir, "firewall.log"),
    ["WebServer"] = Path.Combine(logDir, "webserver.log"),
    ["Auth"]      = Path.Combine(logDir, "auth.log")
});

builder.BuildTimeline();
builder.DetectSuspiciousPatterns();

// Funcție locală: generează fișierele de log demonstrative
static void GenerateSampleLogs(string directory)
{
    Directory.CreateDirectory(directory);

    // Loguri firewall
    File.WriteAllText(
        Path.Combine(directory, "firewall.log"),
        """
        2024-01-15T03:20:01Z ALLOW src=10.0.1.45 dst=203.0.113.50 port=443 proto=TCP
        2024-01-15T03:20:15Z ALLOW src=10.0.1.45 dst=203.0.113.50 port=443 proto=TCP
        2024-01-15T03:22:17Z DENY src=10.0.1.45 dst=198.51.100.77 port=4444 proto=TCP
        2024-01-15T03:24:55Z DENY src=10.0.1.45 dst=198.51.100.77 port=4444 proto=TCP
        2024-01-15T03:25:12Z DENY src=10.0.1.45 dst=198.51.100.77 port=4444 proto=TCP
        2024-01-15T03:26:30Z ALLOW src=10.0.1.45 dst=203.0.113.50 port=443 proto=TCP
        2024-01-15T03:28:00Z DENY src=10.0.1.45 dst=198.51.100.77 port=8080 proto=TCP
        """);

    // Loguri server web
    File.WriteAllText(
        Path.Combine(directory, "webserver.log"),
        """
        10.0.1.45 - - [15/Jan/2024:03:19:22 +0000] "GET / HTTP/1.1" 200 1234
        10.0.1.45 - admin [15/Jan/2024:03:24:51 +0000] "POST /admin/upload HTTP/1.1" 200 4523
        10.0.1.45 - admin [15/Jan/2024:03:25:03 +0000] "GET /admin/users HTTP/1.1" 200 8901
        10.0.1.45 - admin [15/Jan/2024:03:25:30 +0000] "GET /api/export/customers HTTP/1.1" 200 245890
        10.0.1.45 - admin [15/Jan/2024:03:26:15 +0000] "DELETE /admin/logs HTTP/1.1" 200 45
        """);

    // Loguri autentificare
    File.WriteAllText(
        Path.Combine(directory, "auth.log"),
        """
        2024-01-15 03:21:05 UTC AUTH_FAILURE user=admin src=10.0.1.45 method=SSH
        2024-01-15 03:21:18 UTC AUTH_FAILURE user=admin src=10.0.1.45 method=SSH
        2024-01-15 03:21:35 UTC AUTH_FAILURE user=admin src=10.0.1.45 method=SSH
        2024-01-15 03:21:52 UTC AUTH_FAILURE user=admin src=10.0.1.45 method=SSH
        2024-01-15 03:22:08 UTC AUTH_FAILURE user=admin src=10.0.1.45 method=SSH
        2024-01-15 03:24:30 UTC AUTH_SUCCESS user=admin src=10.0.1.45 method=SSH
        """);
}

// ============================================================
// Tipurile de date
// ============================================================

/// <summary>
/// Un eveniment normalizat dintr-un fișier de log,
/// indiferent de sursa sau formatul original.
/// </summary>
record LogEvent(
    DateTime Timestamp,    // întotdeauna în UTC
    string Source,         // Sursa logului: "Firewall", "WebServer", "Auth"
    string Severity,       // INFO, WARNING, ERROR, CRITICAL
    string Description,    // Descrierea evenimentului
    string? SourceIP,      // Adresa IP sursă (dacă este disponibilă)
    string? DestinationIP  // Adresa IP destinație (dacă este disponibilă)
);

/// <summary>
/// Interfață pentru parsarea logurilor din diferite formate.
/// Fiecare sursă de loguri implementează propriul parser.
/// </summary>
interface ILogParser
{
    string SourceName { get; }
    IEnumerable<LogEvent> Parse(string filePath);
}

/// <summary>
/// Parser pentru loguri de firewall.
/// Format: 2024-01-15T03:22:17Z DENY src=10.0.1.45 dst=203.0.113.50
///         port=443 proto=TCP
/// </summary>
class FirewallLogParser : ILogParser
{
    public string SourceName => "Firewall";

    private static readonly Regex LinePattern = new(
        @"^(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+" +
        @"(?<action>ALLOW|DENY)\s+" +
        @"src=(?<src>[\d.]+)\s+" +
        @"dst=(?<dst>[\d.]+)\s+" +
        @"port=(?<port>\d+)\s+" +
        @"proto=(?<proto>\w+)",
        RegexOptions.Compiled);

    public IEnumerable<LogEvent> Parse(string filePath)
    {
        foreach (var line in File.ReadLines(filePath))
        {
            var match = LinePattern.Match(line);
            if (!match.Success) continue;

            var timestamp = DateTime.Parse(
                match.Groups["ts"].Value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal);

            var action = match.Groups["action"].Value;
            var severity = action == "DENY" ? "WARNING" : "INFO";

            yield return new LogEvent(
                timestamp,
                SourceName,
                severity,
                $"{action} {match.Groups["proto"].Value} " +
                $"port {match.Groups["port"].Value}",
                match.Groups["src"].Value,
                match.Groups["dst"].Value);
        }
    }
}

/// <summary>
/// Parser pentru loguri de server web (format Combined Log).
/// Format: 10.0.1.45 - admin [15/Jan/2024:03:24:51 +0000]
///         "POST /admin/upload HTTP/1.1" 200 4523
/// </summary>
class WebServerLogParser : ILogParser
{
    public string SourceName => "WebServer";

    private static readonly Regex LinePattern = new(
        @"^(?<ip>[\d.]+)\s+-\s+(?<user>\S+)\s+" +
        @"\[(?<ts>[^\]]+)\]\s+" +
        @"""(?<method>\w+)\s+(?<path>\S+)\s+HTTP/[\d.]+?""\s+" +
        @"(?<status>\d{3})\s+(?<size>\d+)",
        RegexOptions.Compiled);

    public IEnumerable<LogEvent> Parse(string filePath)
    {
        foreach (var line in File.ReadLines(filePath))
        {
            var match = LinePattern.Match(line);
            if (!match.Success) continue;

            var timestamp = DateTime.ParseExact(
                match.Groups["ts"].Value,
                "dd/MMM/yyyy:HH:mm:ss zzz",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal);

            var status = int.Parse(match.Groups["status"].Value);
            var severity = status >= 500 ? "ERROR"
                         : status >= 400 ? "WARNING"
                         : "INFO";

            yield return new LogEvent(
                timestamp,
                SourceName,
                severity,
                $"{match.Groups["method"].Value} " +
                $"{match.Groups["path"].Value} → " +
                $"{status} ({match.Groups["size"].Value} bytes) " +
                $"user={match.Groups["user"].Value}",
                match.Groups["ip"].Value,
                null);
        }
    }
}

/// <summary>
/// Parser pentru loguri de autentificare.
/// Format: 2024-01-15 03:21:05 UTC AUTH_FAILURE
///         user=admin src=10.0.1.45 method=SSH
/// </summary>
class AuthLogParser : ILogParser
{
    public string SourceName => "Auth";

    private static readonly Regex LinePattern = new(
        @"^(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+" +
        @"(?<event>AUTH_\w+)\s+" +
        @"user=(?<user>\S+)\s+" +
        @"src=(?<src>[\d.]+)\s+" +
        @"method=(?<method>\w+)",
        RegexOptions.Compiled);

    public IEnumerable<LogEvent> Parse(string filePath)
    {
        foreach (var line in File.ReadLines(filePath))
        {
            var match = LinePattern.Match(line);
            if (!match.Success) continue;

            var timestamp = DateTime.ParseExact(
                match.Groups["ts"].Value,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal |
                DateTimeStyles.AdjustToUniversal);

            var eventType = match.Groups["event"].Value;
            var severity = eventType == "AUTH_FAILURE" ? "WARNING"
                         : eventType == "AUTH_SUCCESS" ? "INFO"
                         : "ERROR";

            yield return new LogEvent(
                timestamp,
                SourceName,
                severity,
                $"{eventType} user={match.Groups["user"].Value} " +
                $"method={match.Groups["method"].Value}",
                match.Groups["src"].Value,
                null);
        }
    }
}

/// <summary>
/// Combină evenimentele din surse multiple, le sortează cronologic
/// și identifică tiparele suspecte care pot indica un incident.
/// </summary>
class IncidentTimelineBuilder
{
    private static readonly string Separator = new('═', 70);

    private readonly List<LogEvent> _events = new();
    private readonly List<ILogParser> _parsers = new();

    public void RegisterParser(ILogParser parser) =>
        _parsers.Add(parser);

    /// <summary>
    /// Încarcă logurile din toate fișierele specificate,
    /// aplicând parserul corespunzător fiecăruia.
    /// </summary>
    public void LoadLogs(Dictionary<string, string> sourceFiles)
    {
        foreach (var (parserName, filePath) in sourceFiles)
        {
            var parser = _parsers.FirstOrDefault(
                p => p.SourceName == parserName);
            if (parser == null)
            {
                Console.WriteLine(
                    $"[!] Parser necunoscut: {parserName}");
                continue;
            }

            if (!File.Exists(filePath))
            {
                Console.WriteLine(
                    $"[!] Fișier inexistent: {filePath}");
                continue;
            }

            var events = parser.Parse(filePath).ToList();
            _events.AddRange(events);
            Console.WriteLine(
                $"[+] {events.Count} evenimente din {parserName} " +
                $"({Path.GetFileName(filePath)})");
        }
    }

    /// <summary>
    /// Construiește cronologia sortată și afișează evenimentele.
    /// </summary>
    public void BuildTimeline()
    {
        var sorted = _events.OrderBy(e => e.Timestamp).ToList();

        Console.WriteLine($"\n{Separator}");
        Console.WriteLine(" CRONOLOGIA INCIDENTULUI");
        Console.WriteLine(Separator);
        Console.WriteLine($" Total evenimente: {sorted.Count}");
        Console.WriteLine(
            $" Interval: {sorted.First().Timestamp:u} — " +
            $"{sorted.Last().Timestamp:u}");
        Console.WriteLine($"{Separator}\n");

        foreach (var evt in sorted)
        {
            var icon = evt.Severity switch
            {
                "CRITICAL" => "[!!!]",
                "ERROR"    => "[ERR]",
                "WARNING"  => "[WRN]",
                _          => "[INF]"
            };

            Console.WriteLine(
                $" {evt.Timestamp:u}  {icon,-6} " +
                $"[{evt.Source,-12}] {evt.Description}");

            if (evt.SourceIP != null)
            {
                Console.Write($"{"",22} Src: {evt.SourceIP}");
                if (evt.DestinationIP != null)
                    Console.Write($"  Dst: {evt.DestinationIP}");
                Console.WriteLine();
            }
        }
    }

    /// <summary>
    /// Detectează tipare suspecte: brute force reușit, acces la
    /// resurse sensibile și conexiuni blocate repetat (beaconing).
    /// </summary>
    public void DetectSuspiciousPatterns()
    {
        Console.WriteLine($"\n{Separator}");
        Console.WriteLine(" TIPARE SUSPECTE DETECTATE");
        Console.WriteLine($"{Separator}\n");

        // 1. Brute force: cel puțin 3 eșecuri urmate de un succes
        var authEvents = _events
            .Where(e => e.Source == "Auth")
            .OrderBy(e => e.Timestamp)
            .ToList();

        var failuresByIP = new Dictionary<string, List<LogEvent>>();
        foreach (var evt in authEvents)
        {
            var ip = evt.SourceIP ?? "unknown";

            if (evt.Description.Contains("AUTH_FAILURE"))
            {
                if (!failuresByIP.ContainsKey(ip))
                    failuresByIP[ip] = new List<LogEvent>();
                failuresByIP[ip].Add(evt);
            }
            else if (evt.Description.Contains("AUTH_SUCCESS"))
            {
                if (failuresByIP.TryGetValue(ip, out var failures)
                    && failures.Count >= 3)
                {
                    var window = evt.Timestamp -
                                 failures.First().Timestamp;
                    Console.WriteLine($" [BRUTE FORCE] IP: {ip}");
                    Console.WriteLine(
                        $"   {failures.Count} eșecuri în " +
                        $"{window.TotalMinutes:F1} min, " +
                        "urmate de autentificare reușită");
                    Console.WriteLine(
                        $"   Prima încercare: " +
                        $"{failures.First().Timestamp:u}");
                    Console.WriteLine(
                        $"   Autentificare reușită: {evt.Timestamp:u}");
                    Console.WriteLine();
                }
                failuresByIP.Remove(ip);
            }
        }

        // 2. Acces la resurse sensibile
        var sensitiveAccess = _events
            .Where(e => e.Source == "WebServer" &&
                   (e.Description.Contains("/admin") ||
                    e.Description.Contains("/api/export") ||
                    e.Description.Contains("/backup")))
            .OrderBy(e => e.Timestamp)
            .ToList();

        if (sensitiveAccess.Any())
        {
            Console.WriteLine(
                $" [ACCES SENSIBIL] {sensitiveAccess.Count} accesări " +
                "la resurse administrative/sensibile:");
            foreach (var evt in sensitiveAccess)
                Console.WriteLine(
                    $"   {evt.Timestamp:u}  {evt.Description}");
            Console.WriteLine();
        }

        // 3. Conexiuni blocate repetat către aceeași destinație
        //    externă: tipar de beaconing către un server C2
        var deniedByDst = _events
            .Where(e => e.Source == "Firewall" &&
                   e.Description.StartsWith("DENY"))
            .GroupBy(e => e.DestinationIP)
            .Where(g => g.Count() >= 3)
            .ToList();

        foreach (var group in deniedByDst)
        {
            var ordered = group.OrderBy(e => e.Timestamp).ToList();
            var ports = string.Join(", ", ordered
                .Select(e => e.Description.Split(' ').Last())
                .Distinct());
            Console.WriteLine(
                $" [C2 / BEACONING?] {ordered.Count} conexiuni " +
                $"blocate către {group.Key} (porturi: {ports})");
            Console.WriteLine(
                $"   Interval: {ordered.First().Timestamp:u} — " +
                $"{ordered.Last().Timestamp:u}");
            Console.WriteLine();
        }
    }
}
