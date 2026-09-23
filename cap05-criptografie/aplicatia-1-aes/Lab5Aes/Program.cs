using System.Security.Cryptography;
using System.Text;

// Fișierul de intrare: dacă nu există, îl creăm cu un text de probă
const string inputFile = "mesaj.txt";
if (!File.Exists(inputFile))
    File.WriteAllText(inputFile, "Acesta este un mesaj confidențial care trebuie protejat.");

byte[] plaintextBytes = File.ReadAllBytes(inputFile);
Console.WriteLine($"Fișier citit: {inputFile} ({plaintextBytes.Length} octeți)");

// Cheie AES-256 aleatoare (32 de octeți) și IV aleator pentru CBC (16 octeți = un bloc AES)
byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] iv = RandomNumberGenerator.GetBytes(16);

using var aes = Aes.Create();
aes.Key = key;

// Criptare cu API-urile „one-shot” (disponibile din .NET 6)
byte[] encryptedEcb = aes.EncryptEcb(plaintextBytes, PaddingMode.PKCS7);
byte[] encryptedCbc = aes.EncryptCbc(plaintextBytes, iv, PaddingMode.PKCS7);

// IV-ul nu este secret: se salvează în clar, în fața textului cifrat
File.WriteAllBytes("mesaj.ecb", encryptedEcb);
File.WriteAllBytes("mesaj.cbc", [.. iv, .. encryptedCbc]);

Console.WriteLine($"ECB criptat ({encryptedEcb.Length} octeți): {Convert.ToBase64String(encryptedEcb)}");
Console.WriteLine($"CBC criptat ({encryptedCbc.Length} octeți): {Convert.ToBase64String(encryptedCbc)}");

// Decriptare și verificare
byte[] decryptedEcb = aes.DecryptEcb(encryptedEcb, PaddingMode.PKCS7);
byte[] decryptedCbc = aes.DecryptCbc(encryptedCbc, iv, PaddingMode.PKCS7);
Console.WriteLine($"ECB decriptat: {Encoding.UTF8.GetString(decryptedEcb)}");
Console.WriteLine($"CBC decriptat: {Encoding.UTF8.GetString(decryptedCbc)}");
Console.WriteLine($"Identic cu originalul: {decryptedEcb.SequenceEqual(plaintextBytes) && decryptedCbc.SequenceEqual(plaintextBytes)}");

// ---- Partea B: adăugați în continuarea aceluiași Program.cs ----
// Text cu tipar repetitiv: 3 blocuri identice de câte 16 octeți
string repeating = "BLOCREPETITIV!16BLOCREPETITIV!16BLOCREPETITIV!16";
byte[] repeatingBytes = Encoding.UTF8.GetBytes(repeating);

byte[] ecbResult = aes.EncryptEcb(repeatingBytes, PaddingMode.PKCS7);

// IV NOU pentru acest mesaj. Reutilizarea perechii (cheie, IV) din Partea A ar face ca
// două mesaje cu același început să aibă și același început cifrat.
byte[] iv2 = RandomNumberGenerator.GetBytes(16);
byte[] cbcResult = aes.EncryptCbc(repeatingBytes, iv2, PaddingMode.PKCS7);

PrintBlocks("ECB", ecbResult);
PrintBlocks("CBC", cbcResult);
// În ECB, blocurile 0, 1 și 2 sunt IDENTICE; în CBC sunt diferite.
// Blocul 3 este padding PKCS#7: mesajul are exact 48 de octeți (multiplu de 16),
// așa că se adaugă un bloc întreg de 16 octeți cu valoarea 0x10.

static void PrintBlocks(string label, byte[] data)
{
    Console.WriteLine($"{label} - blocurile cifrate:");
    for (int i = 0; i < data.Length; i += 16)
        Console.WriteLine($"  Bloc {i / 16}: {Convert.ToHexString(data, i, 16)}");
}
