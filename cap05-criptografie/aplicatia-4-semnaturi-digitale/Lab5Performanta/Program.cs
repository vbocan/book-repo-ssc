using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

byte[] testData = Encoding.UTF8.GetBytes("Date de test pentru benchmark semnături digitale.");
const int Iterations = 1000;

using var rsa = RSA.Create(2048);
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

byte[] rsaSig = rsa.SignData(testData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
byte[] ecSig = ecdsa.SignData(testData, HashAlgorithmName.SHA256);

// Încălzire: primele apeluri includ compilarea JIT și inițializarea bibliotecii native
for (int i = 0; i < 50; i++)
{
    rsa.SignData(testData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    rsa.VerifyData(testData, rsaSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    ecdsa.SignData(testData, HashAlgorithmName.SHA256);
    ecdsa.VerifyData(testData, ecSig, HashAlgorithmName.SHA256);
}

Measure("RSA-2048 semnare", () => rsa.SignData(testData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
Measure("RSA-2048 verificare", () => rsa.VerifyData(testData, rsaSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
Measure("ECDSA P-256 semnare", () => ecdsa.SignData(testData, HashAlgorithmName.SHA256));
Measure("ECDSA P-256 verificare", () => ecdsa.VerifyData(testData, ecSig, HashAlgorithmName.SHA256));

Console.WriteLine($"\nDimensiune semnătură RSA: {rsaSig.Length} octeți");
Console.WriteLine($"Dimensiune semnătură ECDSA: {ecSig.Length} octeți");

static void Measure(string label, Action operation)
{
    var sw = Stopwatch.StartNew();
    for (int i = 0; i < Iterations; i++) operation();
    sw.Stop();
    Console.WriteLine($"{label,-24}: {sw.Elapsed.TotalMilliseconds,8:F1} ms ({Iterations} iterații, {sw.Elapsed.TotalMicroseconds / Iterations,7:F1} µs/op)");
}
