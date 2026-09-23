using System.Security.Cryptography;
using System.Text;

// --- Programul principal (top-level statements) ---
// Lista de parole compromise: dacă fișierul lipsește,
// se folosește lista încorporată din clasă.
var manager = new SecurePasswordManager("common-passwords.txt");

(string Password, bool SingleFactor, string Comment)[] tests =
{
    ("password", true, "compromisă"),
    ("abc", true, "prea scurtă"),
    ("ababababababababab", true, "repetitivă"),
    ("munte-lac-2026", true, "14 caractere, factor unic"),
    ("munte-lac-2026", false, "aceeași parolă, în MFA"),
    ("CorectHorseBattery", true, "passphrase de 18 caractere"),
    ("xK9#mP2$vL5@nQ8", true, "aleatoare, 15 caractere")
};

foreach (var (pwd, singleFactor, comment) in tests)
{
    var (isValid, reason) = manager.ValidatePassword(pwd, singleFactor);
    double entropy = SecurePasswordManager.EstimateNaiveEntropy(pwd);
    string mode = singleFactor ? "factor unic" : "MFA";
    Console.WriteLine($"Parola: '{pwd}' ({comment}; mod: {mode})");
    Console.WriteLine($"  Valid: {isValid}: {reason}");
    Console.WriteLine($"  Entropie naivă estimată: {entropy:F1} biți");

    if (isValid)
    {
        string hash = manager.HashPassword(pwd);
        Console.WriteLine($"  Hash: {hash}");
        Console.WriteLine($"  Verificare: {manager.VerifyPassword(pwd, hash)}");
    }
    Console.WriteLine();
}

/// <summary>
/// Validarea și stocarea parolelor conform NIST SP 800-63B-4 (2025).
/// </summary>
public class SecurePasswordManager
{
    private const int SaltSize = 16;          // 128 de biți
    private const int HashSize = 32;          // 256 de biți
    private const int Iterations = 600_000;   // PBKDF2-HMAC-SHA256 (OWASP)

    // SP 800-63B-4: minimum 15 caractere când parola este singurul
    // factor, minimum 8 când face parte dintr-o autentificare MFA.
    private const int MinLengthSingleFactor = 15;
    private const int MinLengthMultiFactor = 8;
    private const int MaxLength = 64;

    // Listă minimă folosită când fișierul extern lipsește.
    private static readonly string[] BuiltInList =
    {
        "123456", "123456789", "12345678", "password", "qwerty",
        "111111", "abc123", "password1", "iloveyou", "admin",
        "welcome", "letmein", "monkey", "dragon", "football",
        "parola", "parola123", "qwertyuiop", "1q2w3e4r",
        "passwordpassword", "123456789012345", "qwertyuiopasdfg"
    };

    private readonly HashSet<string> _commonPasswords;

    public SecurePasswordManager(string commonPasswordsFilePath)
    {
        IEnumerable<string> source;
        if (File.Exists(commonPasswordsFilePath))
        {
            source = File.ReadLines(commonPasswordsFilePath);
            Console.WriteLine($"Lista de parole: {commonPasswordsFilePath}");
        }
        else
        {
            source = BuiltInList;
            Console.WriteLine("Fișierul cu parole comune lipsește; " +
                              "se folosește lista încorporată.");
        }

        // Comparația ignoră diferențele de majuscule/minuscule.
        _commonPasswords = new HashSet<string>(
            source.Select(l => l.Trim()).Where(l => l.Length > 0),
            StringComparer.OrdinalIgnoreCase);
        Console.WriteLine($"Încărcate {_commonPasswords.Count} de parole comune.\n");
    }

    public (bool IsValid, string Reason) ValidatePassword(
        string password, bool isSingleFactor = true)
    {
        if (string.IsNullOrEmpty(password))
            return (false, "Parola nu poate fi goală.");

        // Verificarea contra listei de parole compromise (SHALL)
        if (_commonPasswords.Contains(password))
            return (false, "Parola apare în lista de parole compromise.");

        int minLength = isSingleFactor ? MinLengthSingleFactor
                                       : MinLengthMultiFactor;
        if (password.Length < minLength)
            return (false, $"Parola trebuie să aibă cel puțin {minLength} " +
                           $"caractere (are {password.Length}).");

        if (password.Length > MaxLength)
            return (false, $"Parola depășește {MaxLength} de caractere.");

        if (IsRepetitivePattern(password))
            return (false, "Parola conține un tipar repetitiv.");

        return (true, "Parola îndeplinește cerințele.");
    }

    /// <summary>
    /// Estimare NAIVĂ: lungime × log2(dimensiunea alfabetului).
    /// Supraestimează parolele formate din cuvinte de dicționar.
    /// </summary>
    public static double EstimateNaiveEntropy(string password)
    {
        bool lower = password.Any(char.IsLower);
        bool upper = password.Any(char.IsUpper);
        bool digit = password.Any(char.IsDigit);
        bool other = password.Any(c => !char.IsLetterOrDigit(c));

        int charset = (lower ? 26 : 0) + (upper ? 26 : 0)
                    + (digit ? 10 : 0) + (other ? 32 : 0);
        return charset > 0 ? Math.Log2(charset) * password.Length : 0;
    }

    public string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Derive(password, salt, Iterations, HashSize);
        // Format de stocare: iterații:salt(Base64):hash(Base64)
        return $"{Iterations}:{Convert.ToBase64String(salt)}:" +
               Convert.ToBase64String(hash);
    }

    public bool VerifyPassword(string password, string storedHash)
    {
        string[] parts = storedHash.Split(':');
        if (parts.Length != 3)
            throw new FormatException("Format hash invalid.");

        int iterations = int.Parse(parts[0]);
        byte[] salt = Convert.FromBase64String(parts[1]);
        byte[] expected = Convert.FromBase64String(parts[2]);
        byte[] actual = Derive(password, salt, iterations, expected.Length);

        // Comparare în timp constant (previne atacurile de timing)
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(string password, byte[] salt,
                                 int iterations, int length)
    {
        // Normalizare Unicode (NFC) înainte de hashing, ca aceeași
        // parolă tastată pe sisteme diferite să dea aceiași octeți.
        byte[] bytes = Encoding.UTF8.GetBytes(
            password.Normalize(NormalizationForm.FormC));
        return Rfc2898DeriveBytes.Pbkdf2(bytes, salt, iterations,
                                         HashAlgorithmName.SHA256, length);
    }

    private static bool IsRepetitivePattern(string password)
    {
        if (password.Distinct().Count() == 1)
            return true;

        // Tipare repetitive de lungime 1–3 (ex.: "ababab", "abcabc")
        for (int len = 1; len <= 3; len++)
        {
            if (password.Length < len * 3) continue;
            string pattern = password[..len];
            bool repetitive = true;
            for (int i = len; i < password.Length; i += len)
            {
                int end = Math.Min(i + len, password.Length);
                if (password[i..end] != pattern[..(end - i)])
                {
                    repetitive = false;
                    break;
                }
            }
            if (repetitive) return true;
        }
        return false;
    }
}
