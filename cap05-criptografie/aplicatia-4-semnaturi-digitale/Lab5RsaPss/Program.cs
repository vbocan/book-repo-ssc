using System.Security.Cryptography;
using System.Text;

using var rsa = RSA.Create(2048);

string document = "Contract de prestări servicii nr. 123/2026. Valoare: 50.000 EUR.";
byte[] documentBytes = Encoding.UTF8.GetBytes(document);

// Semnare cu RSA-PSS și SHA-256
byte[] signature = rsa.SignData(documentBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

Console.WriteLine($"Document: {document}");
Console.WriteLine($"Semnătură ({signature.Length} octeți): {Convert.ToBase64String(signature)[..60]}...");

// Verificare pe documentul nemodificat
bool isValid = rsa.VerifyData(documentBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
Console.WriteLine($"Semnătură validă: {isValid}");

// Verificare pe documentul modificat (suma alterată)
string tamperedDocument = "Contract de prestări servicii nr. 123/2026. Valoare: 500.000 EUR.";
byte[] tamperedBytes = Encoding.UTF8.GetBytes(tamperedDocument);
bool isTamperedValid = rsa.VerifyData(tamperedBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
Console.WriteLine($"Semnătură validă pe document modificat: {isTamperedValid}");
