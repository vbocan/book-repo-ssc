using System.Net;
using System.Net.Sockets;
using System.Text;

// ============================================================
// Program principal (instrucțiunile top-level vin primele)
// ============================================================

// Ținta se dă ca argument; implicit, laboratorul local din Docker
string tinta = args.Length > 0 && !args[0].StartsWith("--")
    ? args[0] : "127.0.0.1";
bool autorizat = args.Contains("--am-autorizare-scrisa");

if (!EsteAdresaLocala(tinta) && !autorizat)
{
    Console.WriteLine($"[STOP] {tinta} nu este o adresă locală. " +
        "Scanați doar sisteme pentru care aveți autorizare scrisă " +
        "și adăugați atunci opțiunea --am-autorizare-scrisa.");
    return;
}

// Porturile corespund fișierului docker-compose.yml al laboratorului
var dispozitive = new List<DispozitivIoT>
{
    new(tinta, 2323, TipServiciu.Telnet, "Cameră IP"),
    new(tinta, 8080, TipServiciu.HTTP, "Router IoT, panou web"),
    new(tinta, 1883, TipServiciu.MQTT, "Broker MQTT telemetrie"),
    new(tinta, 1884, TipServiciu.MQTT, "Broker MQTT producție"),
    new(tinta, 2201, TipServiciu.SSH, "Controller automatizare"),
};

Console.WriteLine("=== SCANNER SECURITATE IoT ===");
Console.WriteLine($"Țintă: {tinta}, dispozitive: {dispozitive.Count}");
Console.WriteLine();

var scanner = new ScannerSecuritateIoT(TimeSpan.FromSeconds(2));
var constatari = await scanner.ScaneazaAsync(dispozitive);
ScannerSecuritateIoT.AfiseazaRaport(constatari);

static bool EsteAdresaLocala(string adresa) =>
    adresa == "localhost" ||
    (IPAddress.TryParse(adresa, out var ip) && IPAddress.IsLoopback(ip));

// ============================================================
// Modelul de date
// ============================================================

// DeVerificat = aspect pe care scannerul NU l-a testat efectiv
public enum Severitate { DeVerificat, Scazuta, Medie, Ridicata, Critica }
public enum TipServiciu { Telnet, HTTP, MQTT, SSH, FTP }

public record DispozitivIoT(
    string Adresa, int Port, TipServiciu Serviciu, string Descriere);

public record Constatare(
    string Tinta, Severitate Severitate, string Titlu, string Dovada);

public static class CredentialeImplicite
{
    // Câteva perechi din lista publică folosită de Mirai (2016)
    public static readonly (string Utilizator, string Parola)[] Lista =
    [
        ("admin", "password"), ("root", "root"), ("admin", "1234"),
        ("admin", "admin"), ("user", "user"), ("root", "xc3511"),
    ];
}

// ============================================================
// Scannerul: raportează doar ce a verificat efectiv
// ============================================================

public class ScannerSecuritateIoT(TimeSpan timeout)
{
    private readonly List<Constatare> _constatari = [];

    public async Task<List<Constatare>> ScaneazaAsync(
        IEnumerable<DispozitivIoT> dispozitive)
    {
        _constatari.Clear();
        foreach (var d in dispozitive)
        {
            Console.Write($"[SCAN] {d.Adresa}:{d.Port} ({d.Serviciu}) ... ");
            using var client = await ConecteazaAsync(d.Adresa, d.Port);
            if (client is null)
            {
                Console.WriteLine("port închis");
                continue;
            }
            Console.WriteLine("port deschis");

            switch (d.Serviciu)
            {
                case TipServiciu.Telnet:
                    await VerificaTelnetAsync(d, client); break;
                case TipServiciu.HTTP:
                    await VerificaHttpAsync(d); break;
                case TipServiciu.MQTT:
                    await VerificaMqttAsync(d, client); break;
                default:
                    await VerificaBannerAsync(d, client); break;
            }
        }
        return _constatari;
    }

    private async Task<TcpClient?> ConecteazaAsync(string adresa, int port)
    {
        var client = new TcpClient();
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await client.ConnectAsync(adresa, port, cts.Token);
            return client;
        }
        catch (Exception e)
            when (e is SocketException or OperationCanceledException)
        {
            client.Dispose();
            return null;
        }
    }

    private async Task<byte[]> CitesteAsync(NetworkStream flux, int max = 256)
    {
        var buffer = new byte[max];
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            int n = await flux.ReadAsync(buffer, cts.Token);
            return buffer[..n];
        }
        catch (OperationCanceledException) { return []; }
    }

    private void Adauga(DispozitivIoT d, Severitate s,
        string titlu, string dovada) =>
        _constatari.Add(new($"{d.Adresa}:{d.Port}", s, titlu, dovada));

    private async Task VerificaTelnetAsync(DispozitivIoT d, TcpClient client)
    {
        byte[] raspuns = await CitesteAsync(client.GetStream());
        if (raspuns.Length == 0) return;

        // 0xFF (IAC) marchează o negociere de opțiuni Telnet
        string dovada = raspuns[0] == 0xFF
            ? $"negociere Telnet (IAC), {raspuns.Length} octeți"
            : $"banner: {Encoding.ASCII.GetString(raspuns).Trim()}";
        Adauga(d, Severitate.Ridicata,
            "Telnet activ, credențialele circulă în clar", dovada);
        Adauga(d, Severitate.DeVerificat,
            "Credențialele implicite Telnet nu au fost testate",
            $"testați manual, cu autorizare, cele " +
            $"{CredentialeImplicite.Lista.Length} perechi din listă");
    }

    private async Task VerificaHttpAsync(DispozitivIoT d)
    {
        using var http = new HttpClient { Timeout = timeout };
        string url = $"http://{d.Adresa}:{d.Port}/";
        HttpResponseMessage final = await http.GetAsync(url);

        Adauga(d, Severitate.Ridicata,
            "Panou de administrare prin HTTP, fără TLS",
            $"GET {url} -> {(int)final.StatusCode}");

        if (final.StatusCode == HttpStatusCode.Unauthorized &&
            final.Headers.WwwAuthenticate.Any(h => h.Scheme == "Basic"))
        {
            string? gasit = null;
            foreach (var (utilizator, parola) in CredentialeImplicite.Lista)
            {
                var cerere = new HttpRequestMessage(HttpMethod.Get, url);
                cerere.Headers.Authorization = new("Basic",
                    Convert.ToBase64String(
                        Encoding.UTF8.GetBytes($"{utilizator}:{parola}")));
                var r = await http.SendAsync(cerere);
                if (r.IsSuccessStatusCode)
                {
                    gasit = $"{utilizator}:{parola}";
                    final = r;
                    break;
                }
            }
            if (gasit is not null)
                Adauga(d, Severitate.Critica,
                    "Credențiale implicite acceptate",
                    $"HTTP Basic {gasit} -> 200");
            else
                Adauga(d, Severitate.DeVerificat,
                    "Autentificare HTTP Basic, nicio pereche testată " +
                    "nu a funcționat", "verificați politica de parole");
        }
        else if (final.IsSuccessStatusCode)
        {
            Adauga(d, Severitate.Critica,
                "Panou accesibil fără autentificare",
                $"GET {url} -> 200 fără credențiale");
        }

        string[] necesare =
            ["Content-Security-Policy", "X-Frame-Options",
             "X-Content-Type-Options"];
        var lipsa = necesare.Where(h => !final.Headers.Contains(h));
        if (lipsa.Any())
            Adauga(d, Severitate.Medie, "Header-e de securitate lipsă",
                string.Join(", ", lipsa));

        string server = final.Headers.Server.ToString();
        if (server.Contains('/'))
            Adauga(d, Severitate.Scazuta, "Versiunea serverului este expusă",
                $"Server: {server}");
    }

    private async Task VerificaMqttAsync(DispozitivIoT d, TcpClient client)
    {
        // Pachet MQTT 3.1.1 CONNECT, fără utilizator și parolă
        byte[] id = Encoding.ASCII.GetBytes("scanner-upt");
        byte[] pachet =
        [
            0x10, (byte)(12 + id.Length),            // CONNECT, lungime
            0x00, 0x04, (byte)'M', (byte)'Q', (byte)'T', (byte)'T',
            0x04,                                    // versiunea 3.1.1
            0x02,                                    // clean session
            0x00, 0x3C,                              // keep-alive 60 s
            0x00, (byte)id.Length, .. id             // client ID
        ];

        var flux = client.GetStream();
        await flux.WriteAsync(pachet);
        byte[] connack = await CitesteAsync(flux, 4);
        if (connack.Length < 4 || connack[0] != 0x20) return;

        Adauga(d, Severitate.Ridicata,
            "MQTT fără TLS, mesajele și parolele circulă în clar",
            "brokerul a răspuns la CONNECT pe un port necriptat");
        if (connack[3] == 0x00)
            Adauga(d, Severitate.Critica, "Brokerul acceptă clienți anonimi",
                "CONNACK cod 0 (acceptat) fără credențiale");
        else
            Adauga(d, Severitate.DeVerificat,
                "Brokerul refuză clienții anonimi",
                $"CONNACK cod {connack[3]} (5 = neautorizat); " +
                "verificați ACL-urile pe topic-uri");
    }

    private async Task VerificaBannerAsync(DispozitivIoT d, TcpClient client)
    {
        string banner = Encoding.ASCII.GetString(
            await CitesteAsync(client.GetStream())).Trim();
        if (d.Serviciu == TipServiciu.FTP)
            Adauga(d, Severitate.Ridicata, "FTP activ, date și parole în clar",
                $"banner: {banner}");
        else
            Adauga(d, Severitate.DeVerificat, "SSH activ, configurație netestată",
                $"banner: {banner}; verificați PasswordAuthentication " +
                "și PermitRootLogin");
    }

    public static void AfiseazaRaport(List<Constatare> constatari)
    {
        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("RAPORT SECURITATE IoT");
        Console.WriteLine(new string('=', 60));
        foreach (var grup in constatari.GroupBy(c => c.Severitate)
                                       .OrderByDescending(g => g.Key))
            Console.WriteLine($"  {Eticheta(grup.Key),-15} {grup.Count()}");

        foreach (var grup in constatari.GroupBy(c => c.Tinta))
        {
            Console.WriteLine();
            Console.WriteLine($">>> {grup.Key}");
            foreach (var c in grup.OrderByDescending(c => c.Severitate))
            {
                Console.WriteLine($"  {Eticheta(c.Severitate),-15} {c.Titlu}");
                Console.WriteLine($"  {"",-15} dovadă: {c.Dovada}");
            }
        }
    }

    private static string Eticheta(Severitate s) => s switch
    {
        Severitate.Critica => "[CRITIC]",
        Severitate.Ridicata => "[RIDICAT]",
        Severitate.Medie => "[MEDIU]",
        Severitate.Scazuta => "[SCĂZUT]",
        _ => "[DE VERIFICAT]"
    };
}
