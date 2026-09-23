using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Honeypot;

public static class HealthCheck
{
    private static readonly DateTime StartedAt = DateTime.UtcNow;

    public static async Task StartAsync(HoneypotDatabase db, int port,
        CancellationToken cancellationToken)
    {
        // IPAddress.Any în container; docker-compose publică portul
        // doar pe 127.0.0.1 al gazdei, deci nu e accesibil din Internet
        var listener = new TcpListener(IPAddress.Any, port);
        listener.Start();
        Console.WriteLine($"[*] Health check on port {port}");
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellationToken);
                using var timeout = CancellationTokenSource
                    .CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                try
                {
                    var stream = client.GetStream();
                    // Citim cererea HTTP (fără s-o interpretăm), apoi răspundem
                    _ = await stream.ReadAsync(new byte[1024], timeout.Token);
                    var stats = db.GetBasicStats();
                    var uptime = DateTime.UtcNow - StartedAt;
                    var body = string.Create(CultureInfo.InvariantCulture,
                        $"Status: OK\n" +
                        $"Uptime: {uptime.Days}d {uptime.Hours:D2}:" +
                        $"{uptime.Minutes:D2}\n" +
                        $"TotalConnections: {stats.TotalConnections}\n" +
                        $"LastHour: {stats.ConnectionsLastHour}\n" +
                        $"Last24h: {stats.ConnectionsLast24h}\n" +
                        $"DBSize: {stats.DatabaseSizeMB:F1} MB\n");
                    var response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" +
                        $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n" +
                        "Connection: close\r\n\r\n" + body;
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(response),
                        timeout.Token);
                }
                catch (OperationCanceledException)
                    when (!cancellationToken.IsCancellationRequested) { }
                catch (IOException) { }
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
        }
    }
}
