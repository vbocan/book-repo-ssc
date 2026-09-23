using System.Net;
using Microsoft.Data.Sqlite;

namespace Honeypot;

public record BruteForceAlert(string SourceIP, int Connections, int CredentialAttempts,
    TimeSpan Window);
public record PortScanAlert(string SourceIP, int PortsScanned, TimeSpan Duration);
public record CampaignAlert(string Username, string Password, int SourceIPs,
    int TotalAttempts);

public class AnalysisResult
{
    public Dictionary<int, int> ConnectionsByPort { get; } = new();
    public List<(string IP, int Count, string Network)> TopSourceIPs { get; } = new();
    public Dictionary<string, int> ConnectionsByHour { get; } = new();
    public List<(string Service, string Username, string Password, int Count)>
        TopCredentials { get; } = new();
    public List<(string Client, int Count)> SshClients { get; } = new();
    public List<BruteForceAlert> BruteForceAlerts { get; } = new();
    public List<PortScanAlert> PortScanAlerts { get; } = new();
    public List<CampaignAlert> CampaignAlerts { get; } = new();
}

public class HoneypotAnalyzer
{
    private readonly string _connectionString;

    public HoneypotAnalyzer(string dbPath)
    {
        if (!File.Exists(dbPath))
            throw new FileNotFoundException($"Database not found: {dbPath}");
        _connectionString = $"Data Source={dbPath};Mode=ReadOnly";
    }

    // Fără o bază GeoIP marcăm doar adresele care nu pot veni din Internet
    // (RFC 1918, RFC 6598, RFC 5737). Pentru țări: MaxMind GeoLite2 (vezi textul).
    private static string ClassifyAddress(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return "invalid";
        var b = address.MapToIPv4().GetAddressBytes();
        return b switch
        {
            [10, ..] or [172, >= 16 and <= 31, ..] or [192, 168, ..] => "private",
            [100, >= 64 and <= 127, ..] => "CGNAT",
            [127, ..] => "loopback",
            [192, 0, 2, _] or [198, 51, 100, _] or [203, 0, 113, _] => "documentation",
            _ => "public"
        };
    }

    public AnalysisResult Analyze()
    {
        var result = new AnalysisResult();
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        // Conexiuni pe port
        foreach (var r in Query(conn, @"
            SELECT DestinationPort, COUNT(*) AS cnt
            FROM ConnectionLog GROUP BY DestinationPort ORDER BY cnt DESC"))
            result.ConnectionsByPort[r.GetInt32(0)] = r.GetInt32(1);

        // Top 10 IP-uri sursă
        foreach (var r in Query(conn, @"
            SELECT SourceIP, COUNT(*) AS cnt
            FROM ConnectionLog GROUP BY SourceIP ORDER BY cnt DESC LIMIT 10"))
            result.TopSourceIPs.Add((r.GetString(0), r.GetInt32(1),
                ClassifyAddress(r.GetString(0))));

        // Distribuția pe ore (UTC)
        foreach (var r in Query(conn, @"
            SELECT strftime('%H', Timestamp) AS hour, COUNT(*)
            FROM ConnectionLog GROUP BY hour ORDER BY hour"))
            result.ConnectionsByHour[r.GetString(0)] = r.GetInt32(1);

        // Credențiale: FTP, Telnet, HTTP (formular și Basic). SSH nu apare aici.
        foreach (var r in Query(conn, @"
            SELECT Service, Username, Password, COUNT(*) AS cnt
            FROM CredentialLog
            GROUP BY Service, Username, Password
            ORDER BY cnt DESC, Username LIMIT 10"))
            result.TopCredentials.Add((r.GetString(0), r.GetString(1),
                r.GetString(2), r.GetInt32(3)));

        // Clienți SSH (linia de identificare trimisă în clar)
        foreach (var r in Query(conn, @"
            SELECT i.Data, COUNT(*) AS cnt
            FROM InteractionLog i JOIN ConnectionLog c ON i.ConnectionId = c.Id
            WHERE c.DestinationPort = 22 AND i.Direction = 'RECV'
              AND i.Data LIKE 'SSH-%'
            GROUP BY i.Data ORDER BY cnt DESC LIMIT 5"))
            result.SshClients.Add((r.GetString(0), r.GetInt32(1)));

        // Brute force: în aceeași fereastră de 5 minute, cel puțin 20 de conexiuni
        // sau 10 încercări de autentificare de la același IP. Credențialele se
        // numără întâi pe conexiune, apoi se face JOIN (altfel COUNT se umflă).
        foreach (var r in Query(conn, @"
            SELECT c.SourceIP, COUNT(*) AS conns, SUM(COALESCE(k.n, 0)) AS creds,
                   MIN(c.Timestamp), MAX(c.Timestamp)
            FROM ConnectionLog c
            LEFT JOIN (SELECT ConnectionId, COUNT(*) AS n
                       FROM CredentialLog GROUP BY ConnectionId) k
                   ON k.ConnectionId = c.Id
            GROUP BY c.SourceIP, strftime('%Y-%m-%d %H', c.Timestamp),
                     CAST(strftime('%M', c.Timestamp) AS INTEGER) / 5
            HAVING conns >= 20 OR creds >= 10
            ORDER BY creds DESC, conns DESC"))
            result.BruteForceAlerts.Add(new BruteForceAlert(r.GetString(0),
                r.GetInt32(1), r.GetInt32(2),
                DateTime.Parse(r.GetString(4)) - DateTime.Parse(r.GetString(3))));

        // Scanare de porturi: același IP pe cel puțin 3 porturi în același minut
        foreach (var r in Query(conn, @"
            SELECT SourceIP, COUNT(DISTINCT DestinationPort) AS ports,
                   MIN(Timestamp), MAX(Timestamp)
            FROM ConnectionLog
            GROUP BY SourceIP, strftime('%Y-%m-%d %H:%M', Timestamp)
            HAVING ports >= 3"))
            result.PortScanAlerts.Add(new PortScanAlert(r.GetString(0), r.GetInt32(1),
                DateTime.Parse(r.GetString(3)) - DateTime.Parse(r.GetString(2))));

        // Campanie: aceeași pereche utilizator/parolă de la cel puțin 3 IP-uri
        foreach (var r in Query(conn, @"
            SELECT k.Username, k.Password,
                   COUNT(DISTINCT c.SourceIP) AS ips, COUNT(*) AS attempts
            FROM CredentialLog k JOIN ConnectionLog c ON k.ConnectionId = c.Id
            GROUP BY k.Username, k.Password
            HAVING ips >= 3
            ORDER BY ips DESC, attempts DESC"))
            result.CampaignAlerts.Add(new CampaignAlert(r.GetString(0),
                r.GetString(1), r.GetInt32(2), r.GetInt32(3)));

        return result;
    }

    private static IEnumerable<SqliteDataReader> Query(SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            yield return reader;
    }

    public void PrintReport(AnalysisResult result)
    {
        var line = new string('═', 56);
        Console.WriteLine(line);
        Console.WriteLine("  HONEYPOT ANALYSIS REPORT");
        Console.WriteLine(line);

        Console.WriteLine("\n── Connections by port ──");
        var maxPort = result.ConnectionsByPort.Values.DefaultIfEmpty(1).Max();
        foreach (var (port, count) in result.ConnectionsByPort)
        {
            var service = port switch
            {
                21 => "FTP", 22 => "SSH", 23 => "Telnet", 80 => "HTTP", 443 => "HTTPS",
                _ => $"Port {port}"
            };
            var bar = new string('█', count * 30 / maxPort);
            Console.WriteLine($"  {service,-7} {port,4} │ {count,6} │ {bar}");
        }

        Console.WriteLine("\n── Top source IPs ──");
        foreach (var (ip, count, network) in result.TopSourceIPs)
            Console.WriteLine($"  {ip,-18} {count,6}  {network}");

        Console.WriteLine("\n── Hourly distribution (UTC) ──");
        var maxHour = result.ConnectionsByHour.Values.DefaultIfEmpty(1).Max();
        foreach (var (hour, count) in result.ConnectionsByHour)
            Console.WriteLine(
                $"  {hour}:00 │ {count,6} │ {new string('▓', count * 30 / maxHour)}");

        Console.WriteLine("\n── Top credentials (FTP, Telnet, HTTP) ──");
        foreach (var (service, user, pass, count) in result.TopCredentials)
            Console.WriteLine(
                $"  {service,-12} {Safe(user),-12} {Safe(pass),-16} {count,4}");

        Console.WriteLine("\n── SSH clients (identification string) ──");
        foreach (var (client, count) in result.SshClients)
            Console.WriteLine($"  {Safe(client, 40),-42} {count,4}");

        Console.WriteLine("\n── Brute force ──");
        foreach (var a in result.BruteForceAlerts)
            Console.WriteLine($"  {a.SourceIP,-18} {a.Connections,4} connections, " +
                $"{a.CredentialAttempts,4} credentials in {a.Window.TotalSeconds:F0}s");

        Console.WriteLine("\n── Port scans ──");
        foreach (var a in result.PortScanAlerts)
            Console.WriteLine($"  {a.SourceIP,-18} {a.PortsScanned} ports in " +
                $"{a.Duration.TotalSeconds:F1}s");

        Console.WriteLine("\n── Credential campaigns (same pair, >= 3 IPs) ──");
        foreach (var a in result.CampaignAlerts)
            Console.WriteLine($"  {Safe(a.Username)}:{Safe(a.Password)} from " +
                $"{a.SourceIPs} IPs, {a.TotalAttempts} attempts");

        Console.WriteLine(line);
    }

    private static string Safe(string text, int max = 16) => ConsoleSafe.Clean(text, max);
}
