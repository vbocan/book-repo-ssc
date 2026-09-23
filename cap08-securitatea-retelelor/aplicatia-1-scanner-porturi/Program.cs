using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

// Scanner de porturi TCP (connect scan). Scanați DOAR ținte proprii
// sau scanme.nmap.org, pentru care proiectul Nmap permite scanarea.
string targetHost = args.Length > 0 ? args[0] : "127.0.0.1";
int startPort = 1;
int endPort = 1024;
int timeoutMs = 1000;

var knownServices = new Dictionary<int, string>
{
    { 21, "FTP" }, { 22, "SSH" }, { 23, "Telnet" }, { 25, "SMTP" },
    { 53, "DNS" }, { 80, "HTTP" }, { 110, "POP3" }, { 135, "MS-RPC" },
    { 139, "NetBIOS" }, { 143, "IMAP" }, { 443, "HTTPS" }, { 445, "SMB" },
    { 993, "IMAPS" }, { 995, "POP3S" }, { 3306, "MySQL" },
    { 3389, "RDP" }, { 5432, "PostgreSQL" }, { 8080, "HTTP-Alt" }
};

// Rezoluția DNS se face O SINGURĂ DATĂ, nu pentru fiecare port.
IPAddress target = (await Dns.GetHostAddressesAsync(targetHost))
    .First(a => a.AddressFamily == AddressFamily.InterNetwork);

var openPorts = new ConcurrentBag<int>();
var sw = Stopwatch.StartNew();
Console.WriteLine($"Scanare TCP a porturilor {startPort}-{endPort} " +
                  $"pe {targetHost} ({target})");
Console.WriteLine(new string('-', 60));

// Scanare paralelă: cel mult 100 de conexiuni simultane.
var options = new ParallelOptions { MaxDegreeOfParallelism = 100 };
await Parallel.ForEachAsync(
    Enumerable.Range(startPort, endPort - startPort + 1), options,
    async (port, ct) =>
    {
        using var client = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            await client.ConnectAsync(target, port, cts.Token);
            openPorts.Add(port);                 // conexiune reușită
        }
        catch (OperationCanceledException) { }   // timeout: filtrat?
        catch (SocketException) { }              // refuzat: închis
    });

sw.Stop();
Console.WriteLine($"Scanare completă în {sw.ElapsedMilliseconds} ms\n");
Console.WriteLine($"{"Port",-8}{"Stare",-10}{"Serviciu",-12}Risc de securitate");
Console.WriteLine(new string('-', 60));

foreach (int port in openPorts.OrderBy(p => p))
{
    string service = knownServices.GetValueOrDefault(port, "Necunoscut");
    string risk = port switch
    {
        23 => "Critic: tot traficul în clar",
        445 => "Critic dacă e expus la internet (WannaCry)",
        3389 => "Critic dacă e expus la internet (BlueKeep)",
        21 or 110 or 143 => "Ridicat: credențiale în clar",
        25 => "Mediu: verificați să nu fie relay deschis",
        80 => "Mediu: trafic necriptat",
        _ => "Verificați dacă serviciul este necesar"
    };
    Console.WriteLine($"{port,-8}{"DESCHIS",-10}{service,-12}{risk}");
}

Console.WriteLine($"\nTotal porturi deschise: {openPorts.Count} " +
                  $"din {endPort - startPort + 1} scanate");

int[] cleartext = { 21, 23, 80, 110, 143 };
var insecure = openPorts.Where(p => cleartext.Contains(p)).ToList();
if (insecure.Count > 0)
{
    Console.WriteLine("\nAtenție, protocoale necriptate pe porturile: " +
                      string.Join(", ", insecure.OrderBy(p => p)));
    Console.WriteLine("Înlocuiți FTP→SFTP, Telnet→SSH, HTTP→HTTPS, " +
                      "POP3→POP3S, IMAP→IMAPS.");
}
