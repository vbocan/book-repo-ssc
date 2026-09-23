using System.Security.Cryptography;
using System.Text;

// GREȘIT (doar pentru comparație): SHA-256 simplu, fără salt și fără cost
string password = "P@ssw0rd123";
byte[] unsafeHash = SHA256.HashData(Encoding.UTF8.GetBytes(password));
Console.WriteLine($"SHA-256 simplu (NU folosiți): {Convert.ToHexString(unsafeHash)}");

// CORECT: PBKDF2-HMAC-SHA256, salt aleator, 600.000 de iterații (OWASP, verificat 09.2026)
string stored = HashPassword(password);
Console.WriteLine($"Înregistrare stocată: {stored}");

Console.WriteLine($"Parola corectă acceptată: {VerifyPassword("P@ssw0rd123", stored)}");
Console.WriteLine($"Parola greșită acceptată: {VerifyPassword("P@ssw0rd124", stored)}");

// Aceeași parolă, alt salt: altă înregistrare. Comparația cu == de mai jos arată doar
// că valorile diferă; o parolă se verifică întotdeauna cu VerifyPassword (timp constant).
string stored2 = HashPassword(password);
Console.WriteLine($"A doua înregistrare:  {stored2}");
Console.WriteLine($"Înregistrările sunt identice: {stored == stored2}");

static string HashPassword(string password, int iterations = 600_000)
{
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);
    // Algoritmul, costul și salt-ul se stochează lângă hash, ca să poată fi mărite ulterior
    return $"$pbkdf2-sha256${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
}

static bool VerifyPassword(string password, string stored)
{
    string[] parts = stored.Split('$'); // "", "pbkdf2-sha256", iterații, salt, hash
    if (parts.Length != 5 || parts[1] != "pbkdf2-sha256") return false;
    int iterations = int.Parse(parts[2]);
    byte[] salt = Convert.FromBase64String(parts[3]);
    byte[] expected = Convert.FromBase64String(parts[4]);
    byte[] actual = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
    return CryptographicOperations.FixedTimeEquals(actual, expected);
}
