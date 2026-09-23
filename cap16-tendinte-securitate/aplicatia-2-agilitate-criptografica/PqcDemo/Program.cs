using System.Security.Cryptography;

if (!MLKem.IsSupported || !MLDsa.IsSupported)
{
    Console.WriteLine("ML-KEM/ML-DSA nu sunt disponibile pe această platformă " +
        "(necesită OpenSSL 3.5+ pe Linux sau Windows 11 actualizat).");
    return;
}

// --- ML-KEM-768: încapsularea unei chei (FIPS 203) ---
using MLKem destinatar = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
byte[] cheiePublica = destinatar.ExportEncapsulationKey();

using MLKem expeditor = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, cheiePublica);
expeditor.Encapsulate(out byte[] ciphertext, out byte[] secretExpeditor);
byte[] secretDestinatar = destinatar.Decapsulate(ciphertext);

Console.WriteLine($"ML-KEM-768: cheie publică {cheiePublica.Length} B, " +
    $"ciphertext {ciphertext.Length} B, secret comun {secretExpeditor.Length} B");
Console.WriteLine("Secrete identice: " +
    CryptographicOperations.FixedTimeEquals(secretExpeditor, secretDestinatar));

// --- ML-DSA-65: semnătură digitală (FIPS 204) ---
using MLDsa semnatar = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
byte[] mesaj = "Actualizare firmware v2.1"u8.ToArray();
byte[] semnatura = semnatar.SignData(mesaj);
Console.WriteLine($"ML-DSA-65: semnătură {semnatura.Length} B, " +
    $"verificare: {semnatar.VerifyData(mesaj, semnatura)}");
