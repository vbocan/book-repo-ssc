using System.Text.RegularExpressions;

// ============================================================
// Program principal (instrucțiunile top-level vin primele)
// ============================================================

var analizor = new AnalizorCriptografic();
List<AlgoritmDetectat> detectii;

if (args.Length > 0)
{
    // dotnet run -- <director>: analizează un proiect real
    detectii = analizor.ScaneazaDirector(args[0]);
}
else
{
    // Fără argumente: analizează un fișier de test, tipic pentru o
    // aplicație mai veche, neactualizată
    string codExemplu = """
        using System.Security.Cryptography;

        public class ServiciuAutentificare
        {
            // Problema 1: MD5 pentru parole
            public string HashParola(string parola) =>
                Convert.ToHexString(MD5.HashData(
                    System.Text.Encoding.UTF8.GetBytes(parola)));

            // Problema 2: SHA-1 pentru integritate
            public byte[] Checksum(byte[] date) => SHA1.HashData(date);
        }

        public class ServiciuCriptare
        {
            // Problema 3: DES în modul ECB
            public byte[] CripteazaDES(byte[] date, byte[] cheie)
            {
                using var des = DES.Create();
                des.Key = cheie;
                des.Mode = CipherMode.ECB;
                return des.CreateEncryptor().TransformFinalBlock(
                    date, 0, date.Length);
            }

            // Problema 4: AES-128 (acceptabil, dar de documentat)
            public Aes CreeazaAES()
            {
                var aes = Aes.Create();
                aes.KeySize = 128;
                return aes;
            }

            // Problema 5: criptare RSA cu padding PKCS#1 v1.5
            public byte[] CripteazaCheie(RSA rsa, byte[] cheie) =>
                rsa.Encrypt(cheie, RSAEncryptionPadding.Pkcs1);
        }

        public class ServiciuSemnare
        {
            // Problema 6: semnătură RSA PKCS#1 v1.5
            public byte[] Semneaza(byte[] document)
            {
                using var rsa = RSA.Create(3072);
                var sha = HashAlgorithmName.SHA256;
                return rsa.SignData(document, sha, RSASignaturePadding.Pkcs1);
            }

            // Problema 7: ECDSA pe P-256
            public byte[] SemneazaCuEcc(byte[] document)
            {
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                return ecdsa.SignData(document, HashAlgorithmName.SHA256);
            }

            // Varianta modernă: ML-KEM (FIPS 203)
            public byte[] CheiePublicaPostCuantica()
            {
                using var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
                return kem.ExportEncapsulationKey();
            }
        }
        """;
    Console.WriteLine("=== ANALIZOR DE AGILITATE CRIPTOGRAFICĂ ===");
    detectii = analizor.ScaneazaCod(codExemplu, "ServiciuCripto.cs");
}

analizor.GenereazaRaport(detectii);

// ============================================================
// Modelul de date
// ============================================================

public enum NivelRisc { Sigur, Informativ, Atentie, Depreciat, VulnerabilCuantic }

public record RegulaDetectie(
    string Pattern, string Algoritm, NivelRisc Risc,
    string Explicatie, string Recomandare);

public record AlgoritmDetectat(
    string Fisier, int Linie, string Cod, RegulaDetectie Regula);

// ============================================================
// Baza de reguli (expresii regulate sensibile la majuscule)
// ============================================================

public static class ReguliCriptografice
{
    public static readonly RegulaDetectie[] Reguli =
    [
        new(@"\bMD5\.(Create|HashData)|MD5CryptoServiceProvider",
            "MD5", NivelRisc.Depreciat,
            "Coliziuni practice din 2004.",
            "SHA-256 sau SHA-3; pentru parole, Argon2id sau PBKDF2."),
        new(@"\bSHA1\.(Create|HashData)|SHA1CryptoServiceProvider|SHA1Managed",
            "SHA-1", NivelRisc.Depreciat,
            "Coliziune practică din 2017 (SHAttered). HMAC-SHA1 nu este " +
            "vizat de regulă: nu e spart și apare legitim în TOTP.",
            "SHA-256 sau SHA-3."),
        new(@"\bDES\.Create|DESCryptoServiceProvider",
            "DES", NivelRisc.Depreciat,
            "Cheie de 56 de biți, spartă prin forță brută din 1998.",
            "AES-GCM."),
        new(@"TripleDES",
            "3DES (TDEA)", NivelRisc.Depreciat,
            "NIST a interzis criptarea cu TDEA după 31.12.2023 " +
            "(SP 800-131A Rev. 2).",
            "AES-GCM."),
        new(@"CipherMode\.ECB",
            "Modul ECB", NivelRisc.Depreciat,
            "Blocuri identice de text clar dau blocuri identice de " +
            "text cifrat.",
            "AES-GCM (criptare autentificată)."),
        new(@"RSAEncryptionPadding\.Pkcs1\b",
            "Criptare RSA PKCS#1 v1.5", NivelRisc.Depreciat,
            "Vulnerabilă la atacuri de tip padding oracle " +
            "(Bleichenbacher 1998, ROBOT 2017).",
            "RSAEncryptionPadding.OaepSHA256 sau, mai bine, ML-KEM."),
        new(@"RSASignaturePadding\.Pkcs1\b",
            "Semnătură RSA PKCS#1 v1.5", NivelRisc.Atentie,
            "Permisă de FIPS 186-5; atacurile Bleichenbacher vizează " +
            "criptarea, nu semnătura.",
            "RSASignaturePadding.Pss pentru sisteme noi."),
        new(@"KeySize\s*=\s*1024|RSA\.Create\(\s*1024\s*\)",
            "RSA-1024", NivelRisc.Depreciat,
            "Sub 112 biți de securitate; nepermis de NIST din 2013.",
            "Minimum RSA-2048; pe termen lung, ML-DSA sau ML-KEM."),
        new(@"RSA\.Create|RSACryptoServiceProvider|RSACng|RSAOpenSsl",
            "RSA", NivelRisc.VulnerabilCuantic,
            "Spart de algoritmul lui Shor, indiferent de lungimea cheii.",
            "ML-KEM (FIPS 203) sau ML-DSA (FIPS 204), eventual hibrid."),
        new(@"ECDsa\.Create|ECDiffieHellman\.Create",
            "ECDSA/ECDH", NivelRisc.VulnerabilCuantic,
            "Spart de algoritmul lui Shor, ca și RSA.",
            "ML-DSA pentru semnături, ML-KEM pentru schimbul de chei."),
        new(@"(?<!EC)DiffieHellman",
            "Diffie-Hellman clasic", NivelRisc.VulnerabilCuantic,
            "Spart de algoritmul lui Shor.",
            "ML-KEM sau schimbul hibrid X25519MLKEM768."),
        new(@"KeySize\s*=\s*128\b",
            "AES-128", NivelRisc.Informativ,
            "Acceptat de NIST și în era post-cuantică (categoria 1).",
            "AES-256 pentru date cu viață lungă; obligatoriu în CNSA 2.0."),
        new(@"\b(MLKem|MLDsa|SlhDsa)\b",
            "Algoritm post-cuantic", NivelRisc.Sigur,
            "Standardizat de NIST în FIPS 203/204/205.",
            "Verificați MLKem.IsSupported înainte de utilizare."),
    ];
}

// ============================================================
// Analizorul
// ============================================================

public class AnalizorCriptografic
{
    public List<AlgoritmDetectat> ScaneazaDirector(string director)
    {
        var rezultat = new List<AlgoritmDetectat>();
        if (!Directory.Exists(director))
        {
            Console.WriteLine($"[EROARE] Directorul nu există: {director}");
            return rezultat;
        }
        char sep = Path.DirectorySeparatorChar;
        foreach (var fisier in Directory.EnumerateFiles(
                     director, "*.cs", SearchOption.AllDirectories)
                 .Where(f => !f.Contains($"{sep}bin{sep}") &&
                             !f.Contains($"{sep}obj{sep}")))
        {
            rezultat.AddRange(ScaneazaCod(File.ReadAllText(fisier), fisier));
        }
        return rezultat;
    }

    public List<AlgoritmDetectat> ScaneazaCod(string cod, string numeFisier)
    {
        var rezultat = new List<AlgoritmDetectat>();
        string[] linii = cod.Split('\n');
        for (int i = 0; i < linii.Length; i++)
        {
            string linie = linii[i].Trim();
            if (linie.StartsWith("//") || linie.StartsWith("*"))
                continue;   // comentariile nu sunt cod executabil

            foreach (var regula in ReguliCriptografice.Reguli)
            {
                if (Regex.IsMatch(linie, regula.Pattern))
                    rezultat.Add(new(numeFisier, i + 1, linie, regula));
            }
        }
        return rezultat;
    }

    public void GenereazaRaport(List<AlgoritmDetectat> detectii)
    {
        Console.WriteLine($"Total detecții: {detectii.Count}");
        foreach (var grup in detectii.GroupBy(d => d.Regula.Risc)
                                     .OrderByDescending(g => g.Key))
            Console.WriteLine($"  {Eticheta(grup.Key),-12} {grup.Count()}");

        foreach (var d in detectii.OrderByDescending(d => d.Regula.Risc)
                                  .ThenBy(d => d.Linie))
        {
            Console.WriteLine();
            Console.WriteLine($"{Eticheta(d.Regula.Risc)} {d.Regula.Algoritm}" +
                $" ({Path.GetFileName(d.Fisier)}:{d.Linie})");
            Console.WriteLine($"  Cod:  {d.Cod}");
            Console.WriteLine($"  De ce: {d.Regula.Explicatie}");
            Console.WriteLine($"  Fix:  {d.Regula.Recomandare}");
        }

        Console.WriteLine();
        if (detectii.Any(d => d.Regula.Risc == NivelRisc.Depreciat))
            Console.WriteLine("[ACȚIUNE IMEDIATĂ] Algoritmi depreciați, " +
                "de înlocuit indiferent de amenințarea cuantică.");
        if (detectii.Any(d => d.Regula.Risc == NivelRisc.VulnerabilCuantic))
            Console.WriteLine("[PLANIFICARE] Algoritmi vulnerabili cuantic: " +
                "includeți-i în inventarul criptografic și în planul " +
                "de migrare (NIST IR 8547: depreciați după 2030).");
    }

    private static string Eticheta(NivelRisc risc) => risc switch
    {
        NivelRisc.VulnerabilCuantic => "[CUANTIC]",
        NivelRisc.Depreciat => "[DEPRECIAT]",
        NivelRisc.Atentie => "[ATENȚIE]",
        NivelRisc.Informativ => "[INFO]",
        _ => "[SIGUR]"
    };
}
