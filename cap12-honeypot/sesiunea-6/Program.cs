using System.Globalization;
using System.Runtime.InteropServices;
using Honeypot;

// Output identic pe orice sistem (separator zecimal „.”)
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

var command = args.Length > 0 ? args[0].ToLowerInvariant() : "serve";
var dbPath = Environment.GetEnvironmentVariable("HONEYPOT_DB_PATH") ?? "honeypot.db";

switch (command)
{
    case "serve":
        await RunServerAsync(dbPath);
        return 0;

    case "analyze":
        var analyzer = new HoneypotAnalyzer(args.Length > 1 ? args[1] : dbPath);
        analyzer.PrintReport(analyzer.Analyze());
        return 0;

    case "classify":
        var classifier = new AttackClassifier();
        classifier.Train();
        classifier.ClassifyHoneypotData(args.Length > 1 ? args[1] : dbPath);
        return 0;

    case "backup" when args.Length > 1:
        new HoneypotDatabase(dbPath).BackupTo(args[1]);
        Console.WriteLine($"Backup written to {args[1]}");
        return 0;

    default:
        Console.WriteLine(
            "Usage: Honeypot [serve | analyze [db] | classify [db] | backup <file>]");
        return 1;
}

static async Task RunServerAsync(string dbPath)
{
    var portOffset = int.Parse(
        Environment.GetEnvironmentVariable("HONEYPOT_PORT_OFFSET") ?? "0");
    Console.WriteLine("=== Honeypot Server v1.0 ===");
    Console.WriteLine($"Database: {dbPath}\n");

    using var cts = new CancellationTokenSource();
    // Ctrl+C (SIGINT) la rularea locală, SIGTERM la `docker stop`
    using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT,
        ctx => { ctx.Cancel = true; cts.Cancel(); });
    using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM,
        ctx => { ctx.Cancel = true; cts.Cancel(); });

    var database = new HoneypotDatabase(dbPath);
    var server = new HoneypotServer([21, 22, 23, 80, 443], portOffset, database);
    await Task.WhenAll(
        server.StartAsync(cts.Token),
        HealthCheck.StartAsync(database, 9090, cts.Token));
    Console.WriteLine("[*] Shutting down.");
}
