using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Honeypot;

public class HoneypotServer
{
    private const int MaxConcurrentConnections = 100;

    private readonly int[] _ports;
    private readonly int _portOffset;
    private readonly HoneypotDatabase _database;
    private readonly SemaphoreSlim _slots = new(MaxConcurrentConnections);

    public HoneypotServer(int[] ports, int portOffset, HoneypotDatabase database)
    {
        _ports = ports;
        _portOffset = portOffset;
        _database = database;
    }

    public Task StartAsync(CancellationToken cancellationToken) =>
        Task.WhenAll(_ports.Select(port => ListenOnPortAsync(port, cancellationToken)));

    private async Task ListenOnPortAsync(int servicePort,
        CancellationToken cancellationToken)
    {
        var listenPort = servicePort + _portOffset;
        var listener = new TcpListener(IPAddress.Any, listenPort);
        listener.Start();
        Console.WriteLine($"[*] Listening on port {listenPort} (service {servicePort})");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cancellationToken);
                // Plafonul de conexiuni simultane: peste el, conexiunea se închide
                if (!_slots.Wait(0))
                {
                    client.Dispose();
                    continue;
                }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleClientAsync(client, servicePort, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(
                            $"[!] {ex.GetType().Name}: {ConsoleSafe.Clean(ex.Message)}");
                    }
                    finally
                    {
                        _slots.Release();
                    }
                });
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Stop();
            Console.WriteLine($"[*] Stopped listening on port {listenPort}");
        }
    }

    private async Task HandleClientAsync(TcpClient client, int servicePort,
        CancellationToken cancellationToken)
    {
        using (client)
        {
            var remoteEndPoint = (IPEndPoint)client.Client.RemoteEndPoint!;
            var record = new ConnectionRecord
            {
                Timestamp = DateTime.UtcNow,
                SourceIP = remoteEndPoint.Address.ToString(),
                SourcePort = remoteEndPoint.Port,
                DestinationPort = servicePort,
                InitialData = "" // din sesiunea 2, datele primite ajung în InteractionLog
            };

            var id = _database.LogConnection(record);
            Console.WriteLine(
                $"[{record.Timestamp:HH:mm:ss}] #{id} " +
                $"{record.SourceIP}:{record.SourcePort} " +
                $"-> :{servicePort}");

            var emulator = ServiceRouter.GetEmulator(servicePort);
            if (emulator != null)
                await emulator.HandleConnectionAsync(client.GetStream(), id, _database,
                    cancellationToken);
        }
    }
}

public static class ConsoleSafe
{
    // Datele trimise de atacator pot conține secvențe de control ANSI (ESC[...)
    // care modifică terminalul analistului. Le înlocuim cu „.” înainte de afișare.
    public static string Clean(string text, int maxLength = 120)
    {
        var sb = new StringBuilder();
        foreach (var ch in text)
        {
            if (sb.Length >= maxLength)
            {
                sb.Append("...");
                break;
            }
            sb.Append(char.IsControl(ch) ? '.' : ch);
        }
        return sb.ToString();
    }
}
