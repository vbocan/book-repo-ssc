using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Honeypot;

public interface IServiceEmulator
{
    Task HandleConnectionAsync(NetworkStream stream, long connectionId,
        HoneypotDatabase db, CancellationToken cancellationToken);
}

// Citire și scriere de linii text, comune pentru FTP, Telnet și SSH
public static class LineIO
{
    public static async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct,
        int maxLength = 1024, bool telnet = false)
    {
        var bytes = new List<byte>();
        var one = new byte[1];
        while (bytes.Count < maxLength)
        {
            if (await stream.ReadAsync(one, ct) == 0)
                return bytes.Count > 0 ? Encoding.UTF8.GetString(bytes.ToArray()) : null;
            var b = one[0];
            if (telnet && b == 255)            // IAC: comandă Telnet, nu text
            {
                await SkipTelnetCommandAsync(stream, ct);
                continue;
            }
            if (b == '\n') break;
            if (b != '\r' && b != 0) bytes.Add(b);
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    // IAC WILL/WONT/DO/DONT (251–254) are un octet de opțiune;
    // IAC SB (250) ține până la IAC SE (255 240)
    private static async Task SkipTelnetCommandAsync(Stream stream, CancellationToken ct)
    {
        var buf = new byte[1];
        await stream.ReadExactlyAsync(buf, ct);
        if (buf[0] >= 251 && buf[0] <= 254)
        {
            await stream.ReadExactlyAsync(buf, ct);
        }
        else if (buf[0] == 250)
        {
            byte previous = 0;
            while (true)
            {
                await stream.ReadExactlyAsync(buf, ct);
                if (previous == 255 && buf[0] == 240) break;
                previous = buf[0];
            }
        }
    }

    public static async Task WriteAsync(Stream stream, string text, long connectionId,
        HoneypotDatabase db, CancellationToken ct)
    {
        await stream.WriteAsync(Encoding.UTF8.GetBytes(text), ct);
        db.LogInteraction(connectionId, "SEND", text.Trim());
    }

    public static Task WriteLineAsync(Stream stream, string line, long connectionId,
        HoneypotDatabase db, CancellationToken ct) =>
        WriteAsync(stream, line + "\r\n", connectionId, db, ct);
}

// Emulatorul SSH vede doar partea necriptată a protocolului: linia de identificare
// a clientului și mesajul KEXINIT. NU poate capta parole: autentificarea SSH are loc
// după schimbul de chei, pe un canal deja criptat (RFC 4253, RFC 4252).
public class SshEmulator : IServiceEmulator
{
    private const string Banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19";

    public async Task HandleConnectionAsync(NetworkStream stream, long connectionId,
        HoneypotDatabase db, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource
            .CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            await LineIO.WriteLineAsync(stream, Banner, connectionId, db, cts.Token);

            // 1. Linia de identificare a clientului (RFC 4253, secțiunea 4.2)
            var clientId = await LineIO.ReadLineAsync(stream, cts.Token, maxLength: 255);
            if (clientId is null) return;
            db.LogInteraction(connectionId, "RECV", clientId);
            Console.WriteLine($"  [SSH] Client: {ConsoleSafe.Clean(clientId)}");
            if (!clientId.StartsWith("SSH-")) return;

            // 2. Primul pachet binar: SSH_MSG_KEXINIT (RFC 4253, secțiunea 7.1)
            var header = new byte[5];
            await stream.ReadExactlyAsync(header, cts.Token);
            var packetLength = BinaryPrimitives.ReadInt32BigEndian(header);
            var paddingLength = header[4];
            if (packetLength < 20 || packetLength > 35000) return;
            var packet = new byte[packetLength - 1];
            await stream.ReadExactlyAsync(packet, cts.Token);

            var lists = ParseKexInit(packet, packetLength - 1 - paddingLength);
            if (lists is null) return;

            // HASSH: amprenta MD5 a algoritmilor propuși de client; identifică
            // biblioteca SSH folosită de bot (MD5 e folosit aici doar ca amprentă)
            var hassh = Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(
                $"{lists[0]};{lists[2]};{lists[4]};{lists[6]}")));
            db.LogInteraction(connectionId, "RECV",
                $"KEXINIT ({packetLength} B) hassh={hassh} kex={lists[0]}");
            Console.WriteLine($"  [SSH] KEXINIT hassh={hassh}");
            // Aici un server real ar continua schimbul de chei. Noi închidem conexiunea.
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
    }

    // Structura KEXINIT: tip (1 B) + cookie (16 B) + 10 name-list-uri
    // (kex, host key, enc c2s, enc s2c, mac c2s, mac s2c, comp c2s, ...)
    private static string[]? ParseKexInit(byte[] payload, int payloadLength)
    {
        const byte SshMsgKexInit = 20;
        if (payloadLength < 17 || payloadLength > payload.Length
            || payload[0] != SshMsgKexInit)
            return null;
        var lists = new string[7];
        var offset = 17;
        for (int i = 0; i < lists.Length; i++)
        {
            if (offset + 4 > payloadLength) return null;
            var length = BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(offset));
            offset += 4;
            if (length < 0 || offset + length > payloadLength) return null;
            lists[i] = Encoding.ASCII.GetString(payload, offset, length);
            offset += length;
        }
        return lists;
    }
}

public class FtpEmulator : IServiceEmulator
{
    public async Task HandleConnectionAsync(NetworkStream stream, long connectionId,
        HoneypotDatabase db, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource
            .CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(60));
        var currentUser = "";
        try
        {
            await LineIO.WriteLineAsync(stream, "220 ProFTPD Server (Debian)",
                connectionId, db, cts.Token);

            while (true)
            {
                var input = await LineIO.ReadLineAsync(stream, cts.Token);
                if (input is null) break;
                db.LogInteraction(connectionId, "RECV", input);

                var parts = input.Split(' ', 2);
                var command = parts[0].ToUpperInvariant();
                var argument = parts.Length > 1 ? parts[1] : "";

                switch (command)
                {
                    case "USER":
                        currentUser = argument;
                        await LineIO.WriteLineAsync(stream,
                            $"331 Password required for {argument}",
                            connectionId, db, cts.Token);
                        break;
                    case "PASS" when currentUser != "":
                        db.LogCredential(connectionId, "FTP", currentUser, argument);
                        Console.WriteLine("  [FTP] Credential attempt: " +
                            ConsoleSafe.Clean($"{currentUser}:{argument}"));
                        await Task.Delay(TimeSpan.FromSeconds(1), cts.Token);
                        await LineIO.WriteLineAsync(stream, "530 Login incorrect.",
                            connectionId, db, cts.Token);
                        currentUser = "";
                        break;
                    case "PASS":
                        await LineIO.WriteLineAsync(stream, "503 Login with USER first",
                            connectionId, db, cts.Token);
                        break;
                    case "SYST":
                        await LineIO.WriteLineAsync(stream, "215 UNIX Type: L8",
                            connectionId, db, cts.Token);
                        break;
                    case "QUIT":
                        await LineIO.WriteLineAsync(stream, "221 Goodbye.",
                            connectionId, db, cts.Token);
                        return;
                    default:
                        // Ca un server real: fără autentificare, nimic altceva nu merge
                        Console.WriteLine($"  [FTP] <- {ConsoleSafe.Clean(input)}");
                        await LineIO.WriteLineAsync(stream,
                            "530 Please login with USER and PASS",
                            connectionId, db, cts.Token);
                        break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
    }
}

public class TelnetEmulator : IServiceEmulator
{
    private const string Hostname = "web01";

    public async Task HandleConnectionAsync(NetworkStream stream, long connectionId,
        HoneypotDatabase db, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource
            .CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await LineIO.WriteAsync(stream, "\r\nUbuntu 24.04 LTS\r\n",
                connectionId, db, cts.Token);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                await LineIO.WriteAsync(stream, $"{Hostname} login: ",
                    connectionId, db, cts.Token);
                var user = await LineIO.ReadLineAsync(stream, cts.Token, 256, true);
                if (user is null) return;
                db.LogInteraction(connectionId, "RECV", user);

                await LineIO.WriteAsync(stream, "Password: ",
                    connectionId, db, cts.Token);
                var password = await LineIO.ReadLineAsync(stream, cts.Token, 256, true);
                if (password is null) return;
                db.LogInteraction(connectionId, "RECV", password);

                db.LogCredential(connectionId, "Telnet", user, password);
                Console.WriteLine("  [Telnet] Credential attempt: " +
                    ConsoleSafe.Clean($"{user}:{password}"));
                await Task.Delay(TimeSpan.FromSeconds(2), cts.Token);
                await LineIO.WriteAsync(stream, "\r\nLogin incorrect\r\n",
                    connectionId, db, cts.Token);
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
    }
}

public class HttpEmulator : IServiceEmulator
{
    private const string ServerHeader = "Apache/2.4.58 (Ubuntu)";
    private static readonly Lazy<X509Certificate2> Certificate = new(CreateCertificate);
    private readonly bool _useTls;

    public HttpEmulator(bool useTls = false) => _useTls = useTls;

    private static string LoginPage(string message) => $"""
        <html><head><title>web01 - Administration</title></head>
        <body><h2>Administration login</h2><p>{message}</p>
        <form method="POST" action="/login">
          <input name="username" placeholder="Username"><br>
          <input name="password" type="password" placeholder="Password"><br>
          <button type="submit">Sign in</button>
        </form></body></html>
        """;

    public async Task HandleConnectionAsync(NetworkStream networkStream,
        long connectionId,
        HoneypotDatabase db, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource
            .CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(30));
        Stream stream = networkStream;
        var tag = _useTls ? "HTTPS" : "HTTP";
        try
        {
            if (_useTls)
            {
                var ssl = new SslStream(networkStream, leaveInnerStreamOpen: false);
                stream = ssl;
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = Certificate.Value
                }, cts.Token);
            }

            var request = await ReadRequestAsync(stream, cts.Token);
            if (request is null) return;
            db.LogInteraction(connectionId, "RECV", request);

            var firstLine = request.Split('\n')[0].Trim();
            Console.WriteLine($"  [{tag}] <- {ConsoleSafe.Clean(firstLine)}");
            var parts = firstLine.Split(' ');
            var method = parts[0];
            var path = parts.Length > 1 ? parts[1] : "/";

            // Autentificare HTTP Basic (RFC 7617): utilizator:parolă codificat Base64
            var basic = Regex.Match(request,
                @"(?im)^authorization:\s*basic\s+([A-Za-z0-9+/=]+)");
            if (basic.Success &&
                TryDecodeBasic(basic.Groups[1].Value, out var bUser, out var bPass))
            {
                db.LogCredential(connectionId, $"{tag}-Basic", bUser, bPass);
                Console.WriteLine($"  [{tag}] Basic auth attempt: " +
                    ConsoleSafe.Clean($"{bUser}:{bPass}"));
            }

            string status, body, extraHeaders = "";
            if (method == "POST" && path == "/login")
            {
                var form = ParseForm(request);
                var user = form.GetValueOrDefault("username", "");
                var pass = form.GetValueOrDefault("password", "");
                db.LogCredential(connectionId, $"{tag}-Form", user, pass);
                Console.WriteLine($"  [{tag}] Form login attempt: " +
                    ConsoleSafe.Clean($"{user}:{pass}"));
                status = "200 OK";
                body = LoginPage("Invalid username or password.");
            }
            else if (path.StartsWith("/admin"))
            {
                status = "401 Unauthorized";
                extraHeaders =
                    "WWW-Authenticate: Basic realm=\"web01 administration\"\r\n";
                body = "<html><body><h1>Unauthorized</h1></body></html>";
            }
            else if (path == "/" || path == "/login")
            {
                status = "200 OK";
                body = LoginPage("");
            }
            else
            {
                status = "404 Not Found";
                body = "<html><body><h1>Not Found</h1></body></html>";
            }

            var response = $"HTTP/1.1 {status}\r\n" +
                           $"Date: {DateTime.UtcNow:R}\r\n" +
                           $"Server: {ServerHeader}\r\n" +
                           extraHeaders +
                           $"Content-Type: text/html; charset=UTF-8\r\n" +
                           $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n" +
                           $"Connection: close\r\n\r\n" + body;
            await stream.WriteAsync(Encoding.UTF8.GetBytes(response), cts.Token);
            db.LogInteraction(connectionId, "SEND", $"HTTP {status}");
        }
        catch (AuthenticationException)
        {
            db.LogInteraction(connectionId, "RECV", "[TLS handshake failed]");
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        finally
        {
            if (stream != networkStream) await stream.DisposeAsync();
        }
    }

    // Citim antetele (până la linia goală) și cel mult 4 KB de corp
    private static async Task<string?> ReadRequestAsync(Stream stream,
        CancellationToken ct)
    {
        var buffer = new byte[8192];
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total), ct);
            if (n == 0) break;
            total += n;
            var text = Encoding.Latin1.GetString(buffer, 0, total);
            var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headerEnd < 0) continue;
            var length = Regex.Match(text[..headerEnd],
                @"(?im)^content-length:\s*(\d{1,6})");
            var bodyExpected = length.Success
                ? Math.Min(int.Parse(length.Groups[1].Value), 4096) : 0;
            if (total - (headerEnd + 4) >= bodyExpected) break;
        }
        return total == 0 ? null : Encoding.UTF8.GetString(buffer, 0, total);
    }

    private static Dictionary<string, string> ParseForm(string request)
    {
        var result = new Dictionary<string, string>();
        var bodyStart = request.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (bodyStart < 0) return result;
        foreach (var pair in request[(bodyStart + 4)..].Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2)
                result[kv[0]] = Uri.UnescapeDataString(kv[1].Replace('+', ' '));
        }
        return result;
    }

    private static bool TryDecodeBasic(string value, out string user, out string password)
    {
        user = password = "";
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(value));
            var parts = decoded.Split(':', 2);
            if (parts.Length != 2) return false;
            (user, password) = (parts[0], parts[1]);
            return true;
        }
        catch (FormatException) { return false; }
    }

    // Certificat auto-semnat generat la pornire, pentru portul 443
    private static X509Certificate2 CreateCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=web01", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("web01");
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddYears(1));
        // Export și reîncărcare PFX: cheia privată devine utilizabilă de SslStream
        return X509CertificateLoader.LoadPkcs12(
            certificate.Export(X509ContentType.Pfx), null);
    }
}

public static class ServiceRouter
{
    private static readonly Dictionary<int, IServiceEmulator> Emulators = new()
    {
        [21] = new FtpEmulator(),
        [22] = new SshEmulator(),
        [23] = new TelnetEmulator(),
        [80] = new HttpEmulator(),
        [443] = new HttpEmulator(useTls: true)
    };

    public static IServiceEmulator? GetEmulator(int port) =>
        Emulators.GetValueOrDefault(port);
}
