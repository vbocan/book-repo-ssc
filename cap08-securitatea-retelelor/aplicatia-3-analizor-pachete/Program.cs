using System.Net;
using System.Net.Sockets;

// Analizor simplificat de pachete IPv4, cu trei moduri:
//   dotnet run -- --demo              pachete sintetice (orice SO)
//   dotnet run -- captura.pcap        fișier pcap din Wireshark/tcpdump (orice SO)
//   dotnet run -- --live 192.168.1.23 captură directă (doar Windows, ca Administrator)

var synBySource = new Dictionary<IPAddress, HashSet<int>>();
int packetCount = 0;

try
{
    if (args.Length == 0 || args[0] == "--demo")
    {
        Console.WriteLine("Mod demonstrativ: pachete sintetice\n");
        foreach (byte[] p in DemoPackets.Build())
            Analyze(p, p.Length);
    }
    else if (args[0] == "--live")
    {
        RunLiveWindows(args.Length > 1 ? args[1] : null, maxPackets: 20);
    }
    else
    {
        Console.WriteLine($"Analiză fișier pcap: {Path.GetFileName(args[0])}\n");
        foreach (byte[] p in PcapReader.ReadIPv4Packets(args[0]))
            Analyze(p, p.Length);
    }
}
catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException
                                or IOException or InvalidDataException
                                or UnauthorizedAccessException)
{
    Console.WriteLine($"Eroare: {ex.Message}");
    return;
}

// Corelare în timp: o singură cerere SYN este normală (așa începe
// orice conexiune TCP); multe porturi distincte de la aceeași sursă
// indică o scanare.
const int ScanThreshold = 10;
Console.WriteLine($"\n=== Sumar: pachete IPv4 analizate = {packetCount} ===");
foreach (var (source, ports) in synBySource)
{
    string verdict = ports.Count >= ScanThreshold
        ? "POSIBILĂ SCANARE DE PORTURI" : "normal";
    Console.WriteLine($"{source}: porturi distincte cu SYN = {ports.Count} → {verdict}");
}

void Analyze(byte[] buffer, int length)
{
    if (length < 20 || (buffer[0] >> 4) != 4) return;   // doar IPv4
    packetCount++;

    int headerLength = (buffer[0] & 0x0F) * 4;           // IHL × 4 octeți
    int totalLength = (buffer[2] << 8) | buffer[3];      // octeții 2–3
    int ttl = buffer[8];
    int protocol = buffer[9];
    var src = new IPAddress(buffer.AsSpan(12, 4));
    var dst = new IPAddress(buffer.AsSpan(16, 4));
    string info = $"{totalLength} octeți, TTL {ttl}";

    if (protocol == 6 && length >= headerLength + 14)
    {
        int srcPort = (buffer[headerLength] << 8) | buffer[headerLength + 1];
        int dstPort = (buffer[headerLength + 2] << 8) | buffer[headerLength + 3];
        byte flags = buffer[headerLength + 13];

        var names = new List<string>();
        if ((flags & 0x02) != 0) names.Add("SYN");
        if ((flags & 0x10) != 0) names.Add("ACK");
        if ((flags & 0x01) != 0) names.Add("FIN");
        if ((flags & 0x04) != 0) names.Add("RST");
        if ((flags & 0x08) != 0) names.Add("PSH");
        Console.WriteLine($"[{packetCount}] TCP {src}:{srcPort} → {dst}:{dstPort} " +
                          $"[{string.Join(",", names)}] ({info})");

        bool syn = (flags & 0x02) != 0, ack = (flags & 0x10) != 0;
        if (syn && !ack)
        {
            if (!synBySource.TryGetValue(src, out var set))
                synBySource[src] = set = new HashSet<int>();
            set.Add(dstPort);
        }
        if (syn && (flags & 0x01) != 0)
            Console.WriteLine("    → flag-uri invalide (SYN+FIN): posibilă scanare stealth");
        if (ack && (dstPort is 21 or 23 or 80 or 110 or 143))
            Console.WriteLine("    → protocol necriptat: datele și parolele circulă în clar");
    }
    else if (protocol == 17 && length >= headerLength + 8)
    {
        int srcPort = (buffer[headerLength] << 8) | buffer[headerLength + 1];
        int dstPort = (buffer[headerLength + 2] << 8) | buffer[headerLength + 3];
        string note = dstPort == 53 ? " → interogare DNS" : "";
        Console.WriteLine($"[{packetCount}] UDP {src}:{srcPort} → {dst}:{dstPort} ({info}){note}");
    }
    else
    {
        string name = protocol == 1 ? "ICMP" : $"protocol {protocol}";
        Console.WriteLine($"[{packetCount}] {name} {src} → {dst} ({info})");
    }
}

void RunLiveWindows(string? interfaceIp, int maxPackets)
{
    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException(
            "Captura directă cu SIO_RCVALL există doar pe Windows. Pe Linux/macOS " +
            "capturați cu 'sudo tcpdump -i <interfață> -w captura.pcap' sau cu " +
            "Wireshark și rulați: dotnet run -- captura.pcap");

    var candidates = Dns.GetHostAddresses(Dns.GetHostName())
        .Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
    if (interfaceIp is null)
    {
        Console.WriteLine("Adrese IPv4 locale (alegeți una și rulați din nou " +
                          "cu --live <adresă>):");
        candidates.ForEach(a => Console.WriteLine($"  {a}"));
        return;
    }

    var localIP = IPAddress.Parse(interfaceIp);
    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
    socket.Bind(new IPEndPoint(localIP, 0));
    // SIO_RCVALL: interfața livrează toate pachetele IP care AJUNG la ea.
    // Pe o rețea cu switch, acestea sunt practic doar pachetele proprii
    // și cele de broadcast/multicast.
    socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), new byte[4]);

    var buffer = new byte[65535];
    Console.WriteLine($"Captură pe {localIP}, primele {maxPackets} pachete...\n");
    for (int i = 0; i < maxPackets; i++)
        Analyze(buffer, socket.Receive(buffer));
}

// --- Declarațiile de tip stau după instrucțiunile top-level ---

/// <summary>Cititor minimal pentru formatul pcap clasic (nu pcapng).</summary>
static class PcapReader
{
    public static IEnumerable<byte[]> ReadIPv4Packets(string path)
    {
        using var reader = new BinaryReader(File.OpenRead(path));
        uint magic = reader.ReadUInt32();
        bool swap = magic is 0xD4C3B2A1 or 0x4D3CB2A1;       // big-endian
        if (magic is not (0xA1B2C3D4 or 0xA1B23C4D) && !swap)
            throw new InvalidDataException(
                "Nu este un fișier pcap clasic (salvați din Wireshark ca " +
                "„Wireshark/tcpdump/... - pcap”, nu pcapng).");
        reader.ReadBytes(16);                                 // versiune, zonă, snaplen
        uint linkType = Fix(reader.ReadUInt32(), swap);
        int skip = linkType switch
        {
            1 => 14,      // Ethernet
            101 => 0,     // IP brut
            113 => 16,    // Linux „cooked” (captură pe interfața any)
            _ => throw new InvalidDataException($"Tip de legătură nesuportat: {linkType}")
        };

        while (reader.BaseStream.Position + 16 <= reader.BaseStream.Length)
        {
            reader.ReadBytes(8);                              // timestamp
            int inclLen = (int)Fix(reader.ReadUInt32(), swap);
            reader.ReadUInt32();                              // lungimea originală
            byte[] frame = reader.ReadBytes(inclLen);
            if (frame.Length <= skip) continue;
            // Pentru Ethernet păstrăm doar cadrele IPv4 (EtherType 0x0800)
            if (linkType == 1 && (frame[12] != 0x08 || frame[13] != 0x00)) continue;
            yield return frame[skip..];
        }
    }

    private static uint Fix(uint v, bool swap) =>
        swap ? System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(v) : v;
}

/// <summary>Pachete IPv4 construite manual, pentru modul --demo.</summary>
static class DemoPackets
{
    public static IEnumerable<byte[]> Build()
    {
        var client = IPAddress.Parse("192.168.1.23");
        var server = IPAddress.Parse("192.168.1.10");
        var dns = IPAddress.Parse("192.168.1.1");
        var scanner = IPAddress.Parse("203.0.113.66");

        yield return Tcp(client, server, 51514, 443, 0x02);      // SYN (conexiune normală)
        yield return Tcp(server, client, 443, 51514, 0x12);      // SYN, ACK
        yield return Udp(client, dns, 53001, 53);                // interogare DNS
        yield return Tcp(client, server, 51515, 23, 0x18);       // Telnet, PSH+ACK
        yield return Tcp(scanner, server, 40000, 80, 0x03);      // SYN+FIN
        foreach (int port in new[] { 21, 22, 25, 53, 110, 135, 139, 143, 445, 3389 })
            yield return Tcp(scanner, server, 40001, port, 0x02); // SYN scan
    }

    private static byte[] Tcp(IPAddress s, IPAddress d, int sp, int dp, byte flags)
    {
        byte[] p = Ip(s, d, 6, 20);
        Ports(p, sp, dp);
        p[20 + 12] = 0x50;          // lungimea antetului TCP: 5 × 4 octeți
        p[20 + 13] = flags;
        return p;
    }

    private static byte[] Udp(IPAddress s, IPAddress d, int sp, int dp)
    {
        byte[] p = Ip(s, d, 17, 8);
        Ports(p, sp, dp);
        p[25] = 8;                  // lungimea UDP
        return p;
    }

    private static byte[] Ip(IPAddress s, IPAddress d, byte proto, int payload)
    {
        var p = new byte[20 + payload];
        p[0] = 0x45;                               // IPv4, IHL = 5
        p[2] = (byte)(p.Length >> 8);              // Total Length (octeții 2–3)
        p[3] = (byte)p.Length;
        p[8] = 64;                                 // TTL
        p[9] = proto;
        s.GetAddressBytes().CopyTo(p, 12);
        d.GetAddressBytes().CopyTo(p, 16);
        return p;
    }

    private static void Ports(byte[] p, int sp, int dp)
    {
        p[20] = (byte)(sp >> 8); p[21] = (byte)sp;
        p[22] = (byte)(dp >> 8); p[23] = (byte)dp;
    }
}
