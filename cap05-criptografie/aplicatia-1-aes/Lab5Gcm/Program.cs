using System.Security.Cryptography;
using System.Text;

byte[] key = RandomNumberGenerator.GetBytes(32);

// Nonce de 96 de biți, dimensiunea standard pentru GCM. Cu nonce-uri aleatoare,
// NIST SP 800-38D limitează numărul de criptări cu aceeași cheie la 2^32.
byte[] nonce = RandomNumberGenerator.GetBytes(12);

string message = "Transfer: 50000 EUR către contul RO49AAAA1B31007593840000";
byte[] plaintext = Encoding.UTF8.GetBytes(message);

// Date asociate: autentificate, dar necriptate (de exemplu, antetul unei tranzacții)
byte[] associatedData = Encoding.UTF8.GetBytes("Transaction-ID: TXN-2026-001");

byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[16]; // tag de autentificare de 128 de biți

using (var aesGcm = new AesGcm(key, tag.Length))
{
    aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
}

Console.WriteLine($"Nonce: {Convert.ToHexString(nonce)}");
Console.WriteLine($"Ciphertext: {Convert.ToHexString(ciphertext)}");
Console.WriteLine($"Tag: {Convert.ToHexString(tag)}");

byte[] decrypted = new byte[ciphertext.Length];
using (var aesGcm = new AesGcm(key, tag.Length))
{
    aesGcm.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
}
Console.WriteLine($"Decriptat: {Encoding.UTF8.GetString(decrypted)}");

// Detecția manipulării: modificăm un octet din textul cifrat
ciphertext[0] ^= 0xFF;
try
{
    using var aesGcm2 = new AesGcm(key, tag.Length);
    aesGcm2.Decrypt(nonce, ciphertext, tag, decrypted, associatedData);
    Console.WriteLine("EROARE: Decriptarea nu ar fi trebuit să reușească!");
}
catch (AuthenticationTagMismatchException)
{
    Console.WriteLine("Manipulare detectată! Tag-ul de autentificare nu se potrivește.");
}
