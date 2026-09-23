using System.Security.Cryptography;
using System.Text;

using var rsa = RSA.Create(2048);

string largeMessage = new string('A', 10000); // 10.000 de octeți: imposibil cu RSA direct
byte[] data = Encoding.UTF8.GetBytes(largeMessage);

var (encKey, nonce, cipher, tag) = HybridEncrypt(rsa, data);
byte[] result = HybridDecrypt(rsa, encKey, nonce, cipher, tag);

Console.WriteLine($"Mesaj original: {data.Length} octeți");
Console.WriteLine($"Cheie criptată RSA: {encKey.Length} octeți");
Console.WriteLine($"Mesaj criptat AES: {cipher.Length} octeți");
Console.WriteLine($"Decriptare corectă: {data.SequenceEqual(result)}");

// Expeditorul: criptare hibridă (transportul cheii cu RSA-OAEP)
static (byte[] encryptedKey, byte[] nonce, byte[] ciphertext, byte[] tag) HybridEncrypt(
    RSA recipientPublicKey, byte[] plaintext)
{
    // 1. Cheie AES-256 aleatoare, folosită o singură dată
    byte[] aesKey = RandomNumberGenerator.GetBytes(32);

    // 2. Mesajul se criptează cu AES-GCM
    byte[] nonce = RandomNumberGenerator.GetBytes(12);
    byte[] ciphertext = new byte[plaintext.Length];
    byte[] tag = new byte[16];
    using (var aesGcm = new AesGcm(aesKey, tag.Length))
    {
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
    }

    // 3. Cheia AES se criptează cu cheia publică RSA a destinatarului
    byte[] encryptedKey = recipientPublicKey.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);

    // 4. Cheia AES se șterge din memorie
    CryptographicOperations.ZeroMemory(aesKey);
    return (encryptedKey, nonce, ciphertext, tag);
}

// Destinatarul: decriptare hibridă
static byte[] HybridDecrypt(RSA privateKey, byte[] encryptedKey, byte[] nonce, byte[] ciphertext, byte[] tag)
{
    byte[] aesKey = privateKey.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
    byte[] plaintext = new byte[ciphertext.Length];
    using (var aesGcm = new AesGcm(aesKey, tag.Length))
    {
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
    }
    CryptographicOperations.ZeroMemory(aesKey);
    return plaintext;
}
