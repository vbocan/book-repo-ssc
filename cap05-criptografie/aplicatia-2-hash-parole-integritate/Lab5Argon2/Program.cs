using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

string password = "P@ssw0rd123";

var sw = Stopwatch.StartNew();
string stored = HashPassword(password);
sw.Stop();
Console.WriteLine($"Înregistrare Argon2id: {stored}");
Console.WriteLine($"Timp de calcul: {sw.ElapsedMilliseconds} ms");

Console.WriteLine($"Parola corectă acceptată: {VerifyPassword("P@ssw0rd123", stored)}");
Console.WriteLine($"Parola greșită acceptată: {VerifyPassword("P@ssw0rd124", stored)}");

// Parametrii minimi recomandați de OWASP pentru Argon2id (verificat 09.2026):
// m = 19 MiB, t = 2 iterații, p = 1 fir de execuție
static string HashPassword(string password, int memoryKiB = 19 * 1024, int iterations = 2, int parallelism = 1)
{
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    byte[] hash = Argon2idHash(password, salt, memoryKiB, iterations, parallelism);
    // Format PHC, compatibil cu biblioteca de referință Argon2 și cu alte limbaje
    return $"$argon2id$v=19$m={memoryKiB},t={iterations},p={parallelism}${B64(salt)}${B64(hash)}";
}

static bool VerifyPassword(string password, string stored)
{
    // Părți: "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
    string[] parts = stored.Split('$');
    if (parts.Length != 6 || parts[1] != "argon2id") return false;
    int[] cost = parts[3].Split(',').Select(kv => int.Parse(kv[2..])).ToArray();
    byte[] salt = FromB64(parts[4]);
    byte[] expected = FromB64(parts[5]);
    byte[] actual = Argon2idHash(password, salt, cost[0], cost[1], cost[2]);
    return CryptographicOperations.FixedTimeEquals(actual, expected);
}

static byte[] Argon2idHash(string password, byte[] salt, int memoryKiB, int iterations, int parallelism)
{
    using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
    {
        Salt = salt,
        MemorySize = memoryKiB,
        Iterations = iterations,
        DegreeOfParallelism = parallelism
    };
    return argon2.GetBytes(32);
}

// Base64 fără caracterele de umplere „=”, ca în formatul PHC
static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=');
static byte[] FromB64(string s) => Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
