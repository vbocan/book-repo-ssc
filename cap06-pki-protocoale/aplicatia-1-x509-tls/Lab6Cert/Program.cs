using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

string url = args.Length > 0 ? args[0] : "https://www.google.com";

var handler = new HttpClientHandler
{
    // Callback-ul doar AFIȘEAZĂ certificatul. Decizia rămâne a validării standard
    // (errors == None): nu returnați niciodată „true” necondiționat.
    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
    {
        if (cert != null)
        {
            Console.WriteLine($"Subject: {cert.Subject}");
            Console.WriteLine($"Issuer: {cert.Issuer}");
            Console.WriteLine($"Serial: {cert.SerialNumber}");
            Console.WriteLine($"Valid from: {cert.NotBefore:yyyy-MM-dd} to {cert.NotAfter:yyyy-MM-dd} " +
                              $"({(cert.NotAfter - cert.NotBefore).TotalDays:F0} zile)");
            Console.WriteLine($"Algorithm: {cert.SignatureAlgorithm.FriendlyName}");

            using AsymmetricAlgorithm? publicKey =
                (AsymmetricAlgorithm?)cert.GetRSAPublicKey() ?? cert.GetECDsaPublicKey();
            if (publicKey != null)
                Console.WriteLine($"Key: {publicKey.GetType().Name.Replace("Implementation", "")} {publicKey.KeySize} biți");

            // Numele pentru care e valid certificatul (SAN): aici se verifică potrivirea cu host-ul
            var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            if (san != null)
                Console.WriteLine($"SAN: {string.Join(", ", san.EnumerateDnsNames())}");

            foreach (var ext in cert.Extensions)
                Console.WriteLine($"Extension: {ext.Oid?.FriendlyName} ({ext.Oid?.Value})");
        }

        if (chain != null)
        {
            Console.WriteLine($"\nLanț de certificare ({chain.ChainElements.Count} niveluri):");
            foreach (var element in chain.ChainElements)
                Console.WriteLine($"  - {element.Certificate.Subject}");
        }

        Console.WriteLine($"\nErori SSL: {errors}");
        return errors == SslPolicyErrors.None;
    }
};

using var client = new HttpClient(handler);
try
{
    using var response = await client.GetAsync(url);
    Console.WriteLine($"Răspuns HTTP: {(int)response.StatusCode}");
}
catch (HttpRequestException ex)
{
    Console.WriteLine($"Conexiune refuzată: {ex.InnerException?.Message ?? ex.Message}");
}
