using System.Runtime.InteropServices;
using Honeypot;

var dbPath = Environment.GetEnvironmentVariable("HONEYPOT_DB_PATH") ?? "honeypot.db";
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
await server.StartAsync(cts.Token);
Console.WriteLine("[*] Shutting down.");
