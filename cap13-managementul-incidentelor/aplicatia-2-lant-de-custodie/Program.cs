using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// ============================================================
// Integritatea probelor și lanțul de custodie
// ============================================================

var workDir = Path.Combine(
    Path.GetTempPath(), "forensic-evidence-demo");
Directory.CreateDirectory(workDir);

// Fișiere de probă simulate (în realitate: imagini de zeci de GB)
var evidenceFile1 = Path.Combine(workDir, "disk-image-001.raw");
File.WriteAllText(evidenceFile1,
    "Conținut simulat al unei imagini de disc.\n" +
    "Într-un caz real, fișierul ar avea zeci de gigaocteți " +
    "și ar fi creat cu FTK Imager sau dd.");

var evidenceFile2 = Path.Combine(workDir, "memory-dump-001.mem");
File.WriteAllText(evidenceFile2,
    "Conținut simulat al unei imagini a memoriei RAM.\n" +
    "Într-un caz real, fișierul ar fi creat cu DumpIt " +
    "sau WinPmem.");

var manager = new EvidenceManager(
    Path.Combine(workDir, "custody-log.json"));

Console.WriteLine("SIMULARE: GESTIONAREA PROBELOR DIGITALE\n");

Console.WriteLine("--- Pasul 1: Colectarea probelor ---\n");
var id1 = manager.CollectEvidence(evidenceFile1, "Ana Popescu",
    "Imagine bit cu bit a discului serverului SRV-DB-01");
var id2 = manager.CollectEvidence(evidenceFile2, "Ana Popescu",
    "Imaginea memoriei RAM a serverului SRV-DB-01");

Console.WriteLine("--- Pasul 2: Transferul custodiei ---\n");
manager.TransferCustody(id1, "Ana Popescu", "Mihai Ionescu",
    "Analiza sistemului de fișiere");
manager.TransferCustody(id2, "Mihai Ionescu", "Elena Stan",
    "Transfer cerut de o persoană care NU deține proba");

Console.WriteLine("--- Pasul 3: Simularea alterării unei probe ---\n");
File.AppendAllText(evidenceFile2, "\nDate adăugate ulterior!");
Console.WriteLine("[!] Fișierul memory-dump-001.mem a fost modificat.\n");

Console.WriteLine("--- Pasul 4: Reverificarea integrității ---\n");
manager.VerifyIntegrity(id1);
manager.VerifyIntegrity(id2);
manager.TransferCustody(id2, "Ana Popescu", "Mihai Ionescu",
    "Analiza memoriei");

manager.PrintCustodyChain(id2);

Console.WriteLine("--- Pasul 5: Exportul și verificarea jurnalului ---\n");
manager.ExportCustodyLog();
Console.WriteLine(
    $"Jurnal intact: {EvidenceManager.VerifyLogChain(manager.AllEntries)}");

// ============================================================
// Tipurile de date
// ============================================================

/// <summary>
/// O intrare în lanțul de custodie. PrevEntryHash leagă intrarea
/// de cea anterioară (înlănțuire hash, ca într-un registru
/// append-only): modificarea oricărei intrări vechi rupe lanțul.
/// </summary>
record CustodyEntry(
    int Sequence,
    DateTime TimestampUtc,
    string EvidenceId,
    string Action,        // COLLECTED, TRANSFERRED, INTEGRITY_CHECK ...
    string Handler,       // persoana responsabilă
    string Description,
    string EvidenceHash,  // SHA-256 al probei la momentul acțiunii
    string PrevEntryHash, // hash-ul intrării anterioare din jurnal
    string EntryHash);    // hash-ul acestei intrări

/// <summary>
/// O probă digitală, cu metadatele de colectare.
/// </summary>
class DigitalEvidence
{
    public string EvidenceId { get; init; } = "";
    public string FilePath { get; init; } = "";
    public string OriginalHash { get; init; } = "";
    public long FileSizeBytes { get; init; }
    public string Description { get; init; } = "";
    public string CurrentCustodian { get; set; } = "";
    public bool Compromised { get; set; }
}

/// <summary>
/// Calculează hash-uri, verifică integritatea probelor și ține
/// un jurnal de custodie cu înlănțuire hash.
/// </summary>
class EvidenceManager
{
    private static readonly string Separator = new('═', 64);
    private const string GenesisHash = "0000000000000000";

    private readonly Dictionary<string, DigitalEvidence> _evidence = new();
    private readonly List<CustodyEntry> _log = new();
    private readonly string _custodyLogPath;
    private int _nextId = 1;

    public EvidenceManager(string custodyLogPath) =>
        _custodyLogPath = custodyLogPath;

    public IReadOnlyList<CustodyEntry> AllEntries => _log;

    /// <summary>SHA-256 al unui fișier, citit ca flux (fișiere mari).</summary>
    public static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static string Short(string hash) => hash[..16] + "…";

    private static string HashEntry(int seq, DateTime ts, string id,
        string action, string handler, string description,
        string evidenceHash, string prev)
    {
        var text = string.Join('|', seq, ts.ToString("O"), id, action,
            handler, description, evidenceHash, prev);
        return Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }

    private void Append(string id, string action, string handler,
        string description, string evidenceHash)
    {
        var seq = _log.Count + 1;
        var ts = DateTime.UtcNow;
        var prev = _log.Count == 0 ? GenesisHash : _log[^1].EntryHash;
        var entryHash = HashEntry(seq, ts, id, action, handler,
            description, evidenceHash, prev);
        _log.Add(new CustodyEntry(seq, ts, id, action, handler,
            description, evidenceHash, prev, entryHash));
    }

    public string CollectEvidence(string filePath, string collectedBy,
        string description)
    {
        var id = $"EVD-{_nextId++:D4}";
        var hash = ComputeSha256(filePath);
        var size = new FileInfo(filePath).Length;

        _evidence[id] = new DigitalEvidence
        {
            EvidenceId = id, FilePath = filePath, OriginalHash = hash,
            FileSizeBytes = size, Description = description,
            CurrentCustodian = collectedBy
        };
        Append(id, "COLLECTED", collectedBy,
            $"{description} ({size} bytes)", hash);

        Console.WriteLine($"[+] Probă înregistrată: {id}");
        Console.WriteLine($"    Fișier:      {Path.GetFileName(filePath)}");
        Console.WriteLine($"    Dimensiune:  {size} bytes");
        Console.WriteLine($"    SHA-256:     {hash}");
        Console.WriteLine($"    Colectat de: {collectedBy}\n");
        return id;
    }

    /// <summary>
    /// Recalculează hash-ul și îl compară cu cel de la colectare.
    /// </summary>
    public bool VerifyIntegrity(string id)
    {
        var ev = _evidence[id];
        var current = ComputeSha256(ev.FilePath);
        var ok = current == ev.OriginalHash;
        if (!ok) ev.Compromised = true;

        Append(id, "INTEGRITY_CHECK", ev.CurrentCustodian,
            ok ? "Hash identic cu cel de la colectare"
               : "ALERTĂ: hash diferit de cel de la colectare", current);

        Console.WriteLine($"[=] Verificare integritate: {id}");
        Console.WriteLine($"    Hash la colectare: {Short(ev.OriginalHash)}");
        Console.WriteLine($"    Hash curent:       {Short(current)}");
        Console.WriteLine($"    Status: {(ok ? "VALID" : "COMPROMIS")}\n");
        return ok;
    }

    /// <summary>
    /// Transferă custodia doar dacă predătorul este custodele curent
    /// și proba este intactă; altfel refuză și jurnalizează refuzul.
    /// </summary>
    public bool TransferCustody(string id, string fromHandler,
        string toHandler, string reason)
    {
        var ev = _evidence[id];
        var current = ComputeSha256(ev.FilePath);
        string? problem = null;

        if (ev.CurrentCustodian != fromHandler)
            problem = $"{fromHandler} nu este custodele curent " +
                      $"({ev.CurrentCustodian})";
        else if (current != ev.OriginalHash)
            problem = "hash-ul probei diferă de cel de la colectare";

        if (problem is null)
        {
            ev.CurrentCustodian = toHandler;
            Append(id, "TRANSFERRED", $"{fromHandler} -> {toHandler}",
                reason, current);
            Console.WriteLine(
                $"[>] Transfer {id}: {fromHandler} -> {toHandler} (OK)\n");
            return true;
        }

        Append(id, "TRANSFER_REFUSED", $"{fromHandler} -> {toHandler}",
            problem, current);
        Console.WriteLine(
            $"[X] Transfer {id} REFUZAT: {problem}\n");
        return false;
    }

    public void PrintCustodyChain(string id)
    {
        var ev = _evidence[id];
        Console.WriteLine(Separator);
        Console.WriteLine($" LANȚ DE CUSTODIE: {id}");
        Console.WriteLine($" {ev.Description}");
        Console.WriteLine(Separator);
        foreach (var e in _log.Where(e => e.EvidenceId == id))
        {
            Console.WriteLine(
                $" #{e.Sequence,-2} {e.Action,-16} {e.Handler}");
            Console.WriteLine($"     {e.Description}");
            Console.WriteLine(
                $"     proba: {Short(e.EvidenceHash)}  " +
                $"intrare: {Short(e.EntryHash)}");
        }
        Console.WriteLine($"{Separator}\n");
    }

    /// <summary>
    /// Exportă jurnalul în JSON. Fiecare intrare conține hash-ul
    /// celei anterioare, deci jurnalul poate fi verificat ulterior.
    /// </summary>
    public void ExportCustodyLog()
    {
        var json = JsonSerializer.Serialize(_log,
            new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_custodyLogPath, json);
        Console.WriteLine(
            $"[+] Jurnal exportat: {Path.GetFileName(_custodyLogPath)} " +
            $"({_log.Count} intrări)");
    }

    /// <summary>
    /// Recalculează înlănțuirea: orice intrare modificată, ștearsă
    /// sau inserată ulterior strică verificarea.
    /// </summary>
    public static bool VerifyLogChain(IReadOnlyList<CustodyEntry> log)
    {
        var prev = GenesisHash;
        foreach (var e in log)
        {
            var expected = HashEntry(e.Sequence, e.TimestampUtc,
                e.EvidenceId, e.Action, e.Handler, e.Description,
                e.EvidenceHash, prev);
            if (e.PrevEntryHash != prev || e.EntryHash != expected)
                return false;
            prev = e.EntryHash;
        }
        return true;
    }
}
