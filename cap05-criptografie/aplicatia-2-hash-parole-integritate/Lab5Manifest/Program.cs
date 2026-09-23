using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// Utilizare:  dotnet run -- create <director> <manifest.json>
//             dotnet run -- verify <director> <manifest.json>
// Cheia HMAC (32 de octeți, în hexazecimal) se citește din variabila de mediu MANIFEST_KEY,
// nu din cod. Păstrați manifestul în afara directorului verificat.
if (args.Length != 3 || args[0] is not ("create" or "verify"))
{
    Console.WriteLine("Utilizare: dotnet run -- create|verify <director> <manifest.json>");
    return 1;
}

string? keyHex = Environment.GetEnvironmentVariable("MANIFEST_KEY");
if (keyHex is null || keyHex.Length != 64)
{
    Console.WriteLine("Setați MANIFEST_KEY la o cheie aleatoare de 32 de octeți (64 de cifre hex).");
    return 1;
}
byte[] hmacKey = Convert.FromHexString(keyHex);
string dir = args[1], manifestPath = args[2];

Dictionary<string, string> current = ComputeManifest(dir);

if (args[0] == "create")
{
    var manifest = new Manifest(current, Convert.ToHexString(ComputeMac(current, hmacKey)));
    File.WriteAllText(manifestPath,
        JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"Manifest creat: {current.Count} fișiere -> {manifestPath}");
    return 0;
}

// verify: întâi verificăm HMAC-ul manifestului, apoi fișierele
Manifest saved = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(manifestPath))
                 ?? throw new InvalidDataException("Manifest invalid");
byte[] expectedMac = ComputeMac(saved.Files, hmacKey);
if (!CryptographicOperations.FixedTimeEquals(expectedMac, Convert.FromHexString(saved.Hmac)))
{
    Console.WriteLine("[ALERTĂ] Manifestul a fost modificat (HMAC invalid). Verificarea se oprește.");
    return 2;
}

int changes = 0;
foreach (var (file, hash) in saved.Files.OrderBy(f => f.Key, StringComparer.Ordinal))
{
    if (!current.TryGetValue(file, out string? now)) { Console.WriteLine($"[ȘTERS]     {file}"); changes++; }
    else if (now != hash) { Console.WriteLine($"[MODIFICAT] {file}"); changes++; }
}
foreach (var file in current.Keys.Where(f => !saved.Files.ContainsKey(f)).Order(StringComparer.Ordinal))
{
    Console.WriteLine($"[NOU]       {file}");
    changes++;
}
Console.WriteLine(changes == 0 ? "Integritate OK: nicio modificare." : $"{changes} modificări detectate.");
return changes == 0 ? 0 : 3;

static Dictionary<string, string> ComputeManifest(string directoryPath)
{
    var manifest = new Dictionary<string, string>();
    foreach (var file in Directory.EnumerateFiles(directoryPath, "*", SearchOption.AllDirectories))
    {
        using FileStream stream = File.OpenRead(file);   // citire pe bucăți, nu tot fișierul în memorie
        string relativePath = Path.GetRelativePath(directoryPath, file).Replace('\\', '/');
        manifest[relativePath] = Convert.ToHexString(SHA256.HashData(stream));
    }
    return manifest;
}

static byte[] ComputeMac(Dictionary<string, string> files, byte[] key)
{
    // Reprezentare canonică: câte o linie „cale<TAB>hash” pentru fiecare fișier, în ordine ordinală
    var sb = new StringBuilder();
    foreach (var (path, hash) in files.OrderBy(f => f.Key, StringComparer.Ordinal))
        sb.Append(path).Append('\t').Append(hash).Append('\n');
    return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(sb.ToString()));
}

record Manifest(Dictionary<string, string> Files, string Hmac);
