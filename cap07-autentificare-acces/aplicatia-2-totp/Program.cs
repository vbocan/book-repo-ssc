using System.Security.Cryptography;
using System.Text;

// --- Programul principal (top-level statements) ---

// Pasul 0: verificarea implementării cu vectorul de test din
// RFC 6238, Anexa B (secret ASCII "12345678901234567890", T = 59 s)
byte[] rfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");
string rfcCode = TotpAuthenticator.ComputeTotp(rfcSecret, 59 / 30);
Console.WriteLine("=== Vector de test RFC 6238 ===");
Console.WriteLine($"T = 59 s: {rfcCode} (așteptat 287082)");
Console.WriteLine();

// Pasul 1: generarea secretului partajat (la înrolare)
byte[] secret = TotpAuthenticator.GenerateSecret();
string base32Secret = TotpAuthenticator.EncodeBase32(secret);
string uri = TotpAuthenticator.GenerateOtpAuthUri(
    secret, "SecureApp", "student@upt.ro");

Console.WriteLine("=== Configurare TOTP ===");
Console.WriteLine($"Secret (Base32): {base32Secret}");
Console.WriteLine($"URI: {uri}");
Console.WriteLine();

// Toate calculele folosesc același moment de referință, ca
// rezultatul să nu depindă de trecerea la intervalul următor.
DateTimeOffset now = DateTimeOffset.UtcNow;
long counter = TotpAuthenticator.GetTimeCounter(now);

// Pasul 2: generarea codului curent
string currentCode = TotpAuthenticator.ComputeTotp(secret, counter);
Console.WriteLine("=== Generare cod ===");
Console.WriteLine($"Cod curent: {currentCode}");
Console.WriteLine($"Expiră în: {TotpAuthenticator.SecondsRemaining(now)} secunde");
Console.WriteLine();

// Pasul 3: validarea
Console.WriteLine("=== Validare ===");
Console.WriteLine($"Cod '{currentCode}' valid: " +
    TotpAuthenticator.ValidateCode(secret, currentCode, now));
Console.WriteLine($"Cod '000000' valid: " +
    TotpAuthenticator.ValidateCode(secret, "000000", now));

// Pasul 4: fereastra de toleranță. Codul din intervalul anterior
// (T-1) este acceptat, cel de acum două intervale (T-2) nu.
string previousCode = TotpAuthenticator.ComputeTotp(secret, counter - 1);
string olderCode = TotpAuthenticator.ComputeTotp(secret, counter - 2);
Console.WriteLine($"Cod din intervalul T-1 '{previousCode}' valid: " +
    TotpAuthenticator.ValidateCode(secret, previousCode, now));
Console.WriteLine($"Cod din intervalul T-2 '{olderCode}' valid: " +
    TotpAuthenticator.ValidateCode(secret, olderCode, now));

/// <summary>
/// Implementare TOTP (Time-based One-Time Password) conform RFC 6238.
/// </summary>
public static class TotpAuthenticator
{
    private const int SecretSize = 20;     // 160 de biți (RFC 4226)
    private const int CodeDigits = 6;
    private const int TimeStep = 30;       // secunde
    private const int TimeTolerance = 1;   // ±1 interval

    public static byte[] GenerateSecret() =>
        RandomNumberGenerator.GetBytes(SecretSize);

    /// <summary>Codificare Base32 (RFC 4648), fără padding.</summary>
    public static string EncodeBase32(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var result = new StringBuilder();
        int bits = 0, buffer = 0;

        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                result.Append(alphabet[(buffer >> bits) & 0x1F]);
            }
        }
        if (bits > 0)
            result.Append(alphabet[(buffer << (5 - bits)) & 0x1F]);
        return result.ToString();
    }

    /// <summary>URI otpauth:// pentru aplicațiile de autentificare.</summary>
    public static string GenerateOtpAuthUri(
        byte[] secret, string issuer, string account)
    {
        string s = EncodeBase32(secret);
        string i = Uri.EscapeDataString(issuer);
        string a = Uri.EscapeDataString(account);
        return $"otpauth://totp/{i}:{a}?secret={s}&issuer={i}" +
               $"&algorithm=SHA1&digits={CodeDigits}&period={TimeStep}";
    }

    /// <summary>T = floor(unixTime / TimeStep)</summary>
    public static long GetTimeCounter(DateTimeOffset timestamp) =>
        timestamp.ToUnixTimeSeconds() / TimeStep;

    public static int SecondsRemaining(DateTimeOffset timestamp) =>
        TimeStep - (int)(timestamp.ToUnixTimeSeconds() % TimeStep);

    /// <summary>TOTP = HOTP(secret, T) cu trunchiere dinamică.</summary>
    public static string ComputeTotp(byte[] secret, long timeCounter)
    {
        // Contorul pe 8 octeți, big-endian
        byte[] timeBytes = BitConverter.GetBytes(timeCounter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timeBytes);

        byte[] hmac = HMACSHA1.HashData(secret, timeBytes);

        // Trunchiere dinamică: ultimii 4 biți dau offset-ul
        int offset = hmac[^1] & 0x0F;
        int binaryCode =
            ((hmac[offset] & 0x7F) << 24) |
            (hmac[offset + 1] << 16) |
            (hmac[offset + 2] << 8) |
            hmac[offset + 3];

        int otp = binaryCode % (int)Math.Pow(10, CodeDigits);
        return otp.ToString().PadLeft(CodeDigits, '0');
    }

    /// <summary>Validare cu fereastră de toleranță ±TimeTolerance.</summary>
    public static bool ValidateCode(
        byte[] secret, string code, DateTimeOffset timestamp)
    {
        long current = GetTimeCounter(timestamp);
        for (long i = -TimeTolerance; i <= TimeTolerance; i++)
        {
            string expected = ComputeTotp(secret, current + i);
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(code)))
                return true;
        }
        return false;
    }
}
