using System.Security.Cryptography;
using System.Text;

// Fiecare parte generează o pereche de chei EFEMERĂ (folosită pentru o singură sesiune)
using var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

// Se schimbă doar cheile publice (în TLS 1.3: extensia key_share)
ECDiffieHellmanPublicKey alicePublic = alice.PublicKey;
ECDiffieHellmanPublicKey bobPublic = bob.PublicKey;

// Fiecare calculează secretul comun și derivă din el o cheie AES-256.
// (TLS 1.3 folosește HKDF; aici, pentru simplitate, SHA-256 peste secretul ECDH.)
byte[] aliceKey = alice.DeriveKeyFromHash(bobPublic, HashAlgorithmName.SHA256);
byte[] bobKey = bob.DeriveKeyFromHash(alicePublic, HashAlgorithmName.SHA256);

Console.WriteLine($"Cheia calculată de Alice: {Convert.ToHexString(aliceKey)}");
Console.WriteLine($"Cheia calculată de Bob:   {Convert.ToHexString(bobKey)}");
Console.WriteLine($"Chei identice: {CryptographicOperations.FixedTimeEquals(aliceKey, bobKey)}");

// Cheia comună nu a circulat niciodată pe rețea: se folosește direct cu AES-GCM
byte[] nonce = RandomNumberGenerator.GetBytes(12);
byte[] plaintext = Encoding.UTF8.GetBytes("Mesaj protejat cu o cheie obținută prin ECDH");
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[16];
using (var gcm = new AesGcm(aliceKey, tag.Length))
    gcm.Encrypt(nonce, plaintext, ciphertext, tag);

byte[] received = new byte[ciphertext.Length];
using (var gcm = new AesGcm(bobKey, tag.Length))
    gcm.Decrypt(nonce, ciphertext, tag, received);
Console.WriteLine($"Bob a decriptat: {Encoding.UTF8.GetString(received)}");
