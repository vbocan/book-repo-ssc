using System.Globalization;
using System.Text.RegularExpressions;

// ============================================================
// Analizor de loguri pentru detecția incidentelor
// ============================================================

var workDir = Path.Combine(Path.GetTempPath(), "log-analyzer-demo");
Directory.CreateDirectory(workDir);

var logFile = Path.Combine(workDir, "auth-events.log");
GenerateTestAuthLog(logFile);

Console.WriteLine("ANALIZOR DE LOGURI DE SECURITATE\n");

var analyzer = new AuthLogAnalyzer();
analyzer.LoadLog(logFile);
analyzer.RunFullAnalysis();

// Funcție locală: generează un log de test (ore în UTC)
static void GenerateTestAuthLog(string filePath)
{
    var lines = new List<string>
    {
        // Activitate normală (baseline)
        "2024-01-15 08:01:12 LOGIN_SUCCESS user=maria.pop src=10.0.1.10",
        "2024-01-15 08:15:30 LOGIN_SUCCESS user=ion.radu src=10.0.1.11",
        "2024-01-15 08:30:45 LOGIN_SUCCESS user=elena.stan src=10.0.1.12",
        "2024-01-15 09:00:00 LOGIN_SUCCESS user=maria.pop src=10.0.1.10",
        "2024-01-15 09:15:22 LOGIN_SUCCESS user=ion.radu src=10.0.1.11",
        "2024-01-15 10:00:00 LOGIN_SUCCESS user=sysadmin src=10.0.1.5",
        "2024-01-15 10:30:00 LOGIN_SUCCESS user=elena.stan src=10.0.1.12",
        "2024-01-15 11:00:00 LOGIN_SUCCESS user=maria.pop src=10.0.1.10",
        "2024-01-15 14:00:00 LOGIN_SUCCESS user=ion.radu src=10.0.1.11",
        "2024-01-15 15:30:00 LOGIN_SUCCESS user=elena.stan src=10.0.1.12",

        // Brute force reușit pe contul admin
        "2024-01-15 23:01:05 LOGIN_FAILURE user=admin src=192.168.50.99",
        "2024-01-15 23:01:08 LOGIN_FAILURE user=admin src=192.168.50.99",
        "2024-01-15 23:01:11 LOGIN_FAILURE user=admin src=192.168.50.99",
        "2024-01-15 23:01:14 LOGIN_FAILURE user=admin src=192.168.50.99",
        "2024-01-15 23:01:17 LOGIN_FAILURE user=admin src=192.168.50.99",
        "2024-01-15 23:01:20 LOGIN_FAILURE user=admin src=192.168.50.99",
        "2024-01-15 23:01:23 LOGIN_FAILURE user=admin src=192.168.50.99",
        "2024-01-15 23:02:45 LOGIN_SUCCESS user=admin src=192.168.50.99",

        // Acțiuni de pe contul admin compromis
        "2024-01-15 23:05:00 PRIVILEGE_CHANGE user=admin src=192.168.50.99 role=Domain Admins added for backdoor_user",
        "2024-01-15 23:06:12 ACCOUNT_CREATED user=admin src=192.168.50.99 new_account=backdoor_user",

        // Activitate legitimă de administrare
        "2024-01-16 10:00:00 PRIVILEGE_CHANGE user=sysadmin src=10.0.1.5 role=DB_Read added for elena.stan",

        // Acces anomal: utilizatori obișnuiți de la IP-uri
        // necunoscute, noaptea, în weekend
        "2024-01-20 02:30:00 LOGIN_SUCCESS user=maria.pop src=203.0.113.55",
        "2024-01-20 02:45:00 LOGIN_SUCCESS user=ion.radu src=198.51.100.33",
    };

    File.WriteAllLines(filePath, lines);
}

// ============================================================
// Tipurile de date
// ============================================================

/// <summary>Eveniment de autentificare parsat din log.</summary>
record AuthEvent(
    DateTime Timestamp,  // UTC
    string Username,
    string SourceIP,
    string Action,       // LOGIN_SUCCESS, LOGIN_FAILURE,
                         // PRIVILEGE_CHANGE, ACCOUNT_CREATED
    string Details);

/// <summary>Alertă generată de analizor.</summary>
record SecurityAlert(
    string AlertType,
    string Severity,     // CRITICAL, HIGH, MEDIUM, LOW
    string Description,
    List<AuthEvent> RelatedEvents);

/// <summary>
/// Analizează logurile de autentificare și generează alerte.
/// </summary>
class AuthLogAnalyzer
{
    private static readonly string Separator = new('═', 65);

    private readonly List<AuthEvent> _events = new();
    private readonly List<SecurityAlert> _alerts = new();

    // Conturi (utilizator, IP) compromise prin brute force reușit,
    // cu momentul compromiterii; folosite la corelare.
    private readonly Dictionary<(string User, string IP), DateTime>
        _compromised = new();

    // Praguri de detecție configurabile
    private readonly int _bruteForceThreshold = 5;
    private readonly TimeSpan _bruteForceWindow = TimeSpan.FromMinutes(10);
    private readonly TimeSpan _correlationWindow = TimeSpan.FromHours(1);
    private readonly int _workdayStart = 7;  // 07:00
    private readonly int _workdayEnd = 20;   // 20:00

    private static readonly Regex EventPattern = new(
        @"^(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+" +
        @"(?<action>\w+)\s+" +
        @"user=(?<user>\S+)\s+" +
        @"src=(?<src>[\d.]+)" +
        @"(?:\s+(?<details>.*))?$",
        RegexOptions.Compiled);

    public void LoadLog(string filePath)
    {
        foreach (var line in File.ReadLines(filePath))
        {
            var match = EventPattern.Match(line);
            if (!match.Success) continue;

            // Orele din log sunt UTC: o spunem explicit la parsare
            var ts = DateTime.ParseExact(match.Groups["ts"].Value,
                "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal |
                DateTimeStyles.AdjustToUniversal);

            _events.Add(new AuthEvent(ts,
                match.Groups["user"].Value,
                match.Groups["src"].Value,
                match.Groups["action"].Value,
                match.Groups["details"].Value));
        }

        Console.WriteLine(
            $"[+] {_events.Count} evenimente încărcate " +
            $"din {Path.GetFileName(filePath)}\n");
    }

    /// <summary>
    /// Brute force: cel puțin N eșecuri de la același IP pentru
    /// același cont într-o fereastră de timp.
    /// </summary>
    public void DetectBruteForce()
    {
        var groups = _events
            .Where(e => e.Action == "LOGIN_FAILURE")
            .GroupBy(e => (e.Username, e.SourceIP));

        foreach (var group in groups)
        {
            var sorted = group.OrderBy(e => e.Timestamp).ToList();

            for (int i = 0; i <= sorted.Count - _bruteForceThreshold; i++)
            {
                var windowEnd = sorted[i].Timestamp + _bruteForceWindow;
                var inWindow = sorted.Skip(i)
                    .TakeWhile(e => e.Timestamp <= windowEnd).ToList();
                if (inWindow.Count < _bruteForceThreshold) continue;

                var last = inWindow[^1].Timestamp;
                var success = _events.FirstOrDefault(e =>
                    e.Action == "LOGIN_SUCCESS" &&
                    e.Username == group.Key.Username &&
                    e.SourceIP == group.Key.SourceIP &&
                    e.Timestamp > last &&
                    e.Timestamp <= last + TimeSpan.FromMinutes(30));

                var related = new List<AuthEvent>(inWindow);
                if (success is not null)
                {
                    related.Add(success);
                    _compromised[(group.Key.Username, group.Key.SourceIP)]
                        = success.Timestamp;
                }

                _alerts.Add(new SecurityAlert("BRUTE_FORCE",
                    success is not null ? "CRITICAL" : "HIGH",
                    (success is not null ? "Brute force REUȘIT: " : "Brute force: ") +
                    $"{inWindow.Count} eșecuri pentru {group.Key.Username} " +
                    $"de la {group.Key.SourceIP}",
                    related));
                break; // o singură alertă per grup
            }
        }
    }

    /// <summary>
    /// Schimbări de privilegii și creări de conturi. Severitatea
    /// rezultă din corelare: o acțiune făcută de pe un cont și IP
    /// compromise prin brute force în ultima oră este CRITICAL,
    /// chiar dacă vine de la un administrator „cunoscut”.
    /// </summary>
    public void DetectPrivilegeEscalation()
    {
        var knownAdmins = new HashSet<string> { "sysadmin", "admin", "root" };

        foreach (var evt in _events.Where(e =>
                     e.Action is "PRIVILEGE_CHANGE" or "ACCOUNT_CREATED"))
        {
            var what = evt.Action == "ACCOUNT_CREATED"
                ? "Cont creat" : "Modificare privilegii";
            var desc = $"{what} de {evt.Username} de la " +
                       $"{evt.SourceIP}: {evt.Details}";

            bool afterCompromise =
                _compromised.TryGetValue((evt.Username, evt.SourceIP),
                    out var compromisedAt) &&
                evt.Timestamp >= compromisedAt &&
                evt.Timestamp - compromisedAt <= _correlationWindow;

            string severity;
            if (afterCompromise)
            {
                severity = "CRITICAL";
                desc = $"[CONT COMPROMIS] {desc}";
            }
            else if (!knownAdmins.Contains(evt.Username))
            {
                severity = "HIGH";
                desc = $"[NEAUTORIZAT] {desc}";
            }
            else
            {
                severity = "MEDIUM"; // de confirmat cu tichetul de schimbare
            }

            _alerts.Add(new SecurityAlert("PRIVILEGE_ESCALATION",
                severity, desc, new List<AuthEvent> { evt }));
        }
    }

    /// <summary>
    /// Acces anomal: autentificări în afara programului, în weekend
    /// sau de la IP-uri noi pentru utilizator.
    /// </summary>
    public void DetectAnomalousAccess()
    {
        var successEvents = _events
            .Where(e => e.Action == "LOGIN_SUCCESS")
            .OrderBy(e => e.Timestamp).ToList();

        // Primele 70% din autentificările reușite formează baseline-ul
        var baselineCount = (int)(successEvents.Count * 0.7);
        var knownIPs = successEvents.Take(baselineCount)
            .GroupBy(e => e.Username)
            .ToDictionary(g => g.Key,
                g => g.Select(e => e.SourceIP).ToHashSet());

        foreach (var evt in successEvents.Skip(baselineCount))
        {
            var anomalies = new List<string>();

            if (evt.Timestamp.Hour < _workdayStart ||
                evt.Timestamp.Hour >= _workdayEnd)
                anomalies.Add($"ora neobișnuită ({evt.Timestamp:HH:mm})");

            if (knownIPs.TryGetValue(evt.Username, out var ips) &&
                !ips.Contains(evt.SourceIP))
                anomalies.Add($"IP necunoscut ({evt.SourceIP})");

            if (evt.Timestamp.DayOfWeek is DayOfWeek.Saturday
                or DayOfWeek.Sunday)
                anomalies.Add("acces în weekend");

            if (anomalies.Count > 0)
                _alerts.Add(new SecurityAlert("ANOMALOUS_ACCESS",
                    anomalies.Count >= 2 ? "HIGH" : "MEDIUM",
                    $"Acces anomal: {evt.Username} de la {evt.SourceIP}: " +
                    string.Join(", ", anomalies),
                    new List<AuthEvent> { evt }));
        }
    }

    public void RunFullAnalysis()
    {
        DetectBruteForce();          // trebuie să ruleze primul (corelare)
        DetectPrivilegeEscalation();
        DetectAnomalousAccess();
        PrintReport();
    }


    // Împarte un text lung pe mai multe rânduri (lățime maximă dată)
    private static IEnumerable<string> Wrap(string text, int width)
    {
        var line = "";
        foreach (var word in text.Split(' '))
        {
            if (line.Length > 0 && line.Length + 1 + word.Length > width)
            {
                yield return line;
                line = word;
            }
            else line = line.Length == 0 ? word : line + " " + word;
        }
        if (line.Length > 0) yield return line;
    }

    private void PrintReport()
    {
        int Count(string s) => _alerts.Count(a => a.Severity == s);

        Console.WriteLine(Separator);
        Console.WriteLine(" RAPORT DE ANALIZĂ A LOGURILOR DE SECURITATE");
        Console.WriteLine(Separator);
        Console.WriteLine($" Total evenimente analizate: {_events.Count}");
        Console.WriteLine($" Alerte generate: {_alerts.Count}");
        Console.WriteLine($"   CRITICAL: {Count("CRITICAL")}");
        Console.WriteLine($"   HIGH:     {Count("HIGH")}");
        Console.WriteLine($"   MEDIUM:   {Count("MEDIUM")}");
        Console.WriteLine($"{Separator}\n");

        var order = new Dictionary<string, int>
            { ["CRITICAL"] = 0, ["HIGH"] = 1, ["MEDIUM"] = 2, ["LOW"] = 3 };

        int n = 1;
        foreach (var alert in _alerts
                     .OrderBy(a => order.GetValueOrDefault(a.Severity, 99))
                     .ThenBy(a => a.RelatedEvents[0].Timestamp))
        {
            var marker = alert.Severity switch
            {
                "CRITICAL" => "[!!!]",
                "HIGH"     => "[!! ]",
                "MEDIUM"   => "[!  ]",
                _          => "[   ]"
            };

            Console.WriteLine(
                $" {marker} Alerta #{n++}: {alert.AlertType} ({alert.Severity})");
            foreach (var l in Wrap(alert.Description, 58))
                Console.WriteLine($"       {l}");

            foreach (var evt in alert.RelatedEvents.Take(2))
                Console.WriteLine(
                    $"         {evt.Timestamp:yyyy-MM-dd HH:mm:ss} UTC " +
                    $"{evt.Action} user={evt.Username}");

            if (alert.RelatedEvents.Count > 2)
                Console.WriteLine(
                    $"         ... și alte {alert.RelatedEvents.Count - 2} evenimente");
            Console.WriteLine();
        }
    }
}
