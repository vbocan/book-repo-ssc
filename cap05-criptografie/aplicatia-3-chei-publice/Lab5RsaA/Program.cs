using System.Security.Cryptography;
using System.Text;

// Generarea unei perechi de chei RSA-2048
using var rsa = RSA.Create(2048);

// Exportăm doar cheia publică (format PEM, SubjectPublicKeyInfo).
// Cheia privată NU se exportă necriptată; dacă trebuie salvată, folosiți
// rsa.ExportEncryptedPkcs8PrivateKeyPem(parola, new PbeParameters(...)).
string publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
Console.WriteLine("=== Cheie publică ===");
Console.WriteLine(publicKeyPem[..100] + "...");

// Criptarea unui mesaj scurt cu cheia publică (RSA-OAEP cu SHA-256)
string message = "Cheie de sesiune: AES-256-GCM-KEY-abc123def456";
byte[] messageBytes = Encoding.UTF8.GetBytes(message);

byte[] encrypted = rsa.Encrypt(messageBytes, RSAEncryptionPadding.OaepSHA256);
Console.WriteLine($"\nMesaj criptat ({encrypted.Length} octeți): {Convert.ToBase64String(encrypted)[..60]}...");

// Decriptarea cu cheia privată
byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
Console.WriteLine($"Mesaj decriptat: {Encoding.UTF8.GetString(decrypted)}");

// Limita de dimensiune: RSA-2048 cu OAEP-SHA256 criptează cel mult
// 256 - 2*32 - 2 = 190 de octeți
byte[] largeMessage = new byte[191];
try
{
    rsa.Encrypt(largeMessage, RSAEncryptionPadding.OaepSHA256);
}
catch (CryptographicException ex)
{
    Console.WriteLine($"\nEroare la mesaj prea mare: {ex.Message}");
    Console.WriteLine("Soluție: folosiți criptarea hibridă (RSA + AES)!");
}
