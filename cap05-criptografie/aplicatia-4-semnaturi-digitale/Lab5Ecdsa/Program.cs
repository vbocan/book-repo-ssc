using System.Security.Cryptography;
using System.Text;

// Generarea cheilor ECDSA pe curba P-256
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

string message = "Tranzacție: transfer 1000 EUR din contul A în contul B";
byte[] messageBytes = Encoding.UTF8.GetBytes(message);

// Implicit, .NET produce formatul IEEE P1363: r || s, 64 de octeți pentru P-256
byte[] ecSignature = ecdsa.SignData(messageBytes, HashAlgorithmName.SHA256);
Console.WriteLine($"Semnătură ECDSA P1363 ({ecSignature.Length} octeți): {Convert.ToHexString(ecSignature)[..60]}...");

// OpenSSL, X.509 și TLS folosesc codificarea DER (SEQUENCE { r, s }), de 70-72 de octeți
byte[] derSignature = ecdsa.SignData(messageBytes, HashAlgorithmName.SHA256,
    DSASignatureFormat.Rfc3279DerSequence);
Console.WriteLine($"Semnătură ECDSA DER ({derSignature.Length} octeți): {Convert.ToHexString(derSignature)[..60]}...");

bool ecValid = ecdsa.VerifyData(messageBytes, ecSignature, HashAlgorithmName.SHA256);
bool derValid = ecdsa.VerifyData(messageBytes, derSignature, HashAlgorithmName.SHA256,
    DSASignatureFormat.Rfc3279DerSequence);
Console.WriteLine($"ECDSA validă (P1363): {ecValid}, (DER): {derValid}");

// Două semnări ale aceluiași mesaj dau rezultate diferite: k este ales aleator
byte[] second = ecdsa.SignData(messageBytes, HashAlgorithmName.SHA256);
Console.WriteLine($"Semnăturile succesive sunt identice: {ecSignature.SequenceEqual(second)}");
