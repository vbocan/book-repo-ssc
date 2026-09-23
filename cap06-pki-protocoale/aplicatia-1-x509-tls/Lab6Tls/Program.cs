using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

string host = args.Length > 0 ? args[0] : "www.google.com";
const int Port = 443;

using var tcp = new TcpClient();
await tcp.ConnectAsync(host, Port);

// Fără callback de validare: SslStream verifică lanțul de certificare, perioada de
// valabilitate și potrivirea numelui cu TargetHost. NU folosiți callback-ul
// „(sender, cert, chain, errors) => true”: acceptă orice certificat, deci orice atacator MITM.
using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
try
{
    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
    {
        TargetHost = host,
        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
    });
}
catch (AuthenticationException ex)
{
    Console.WriteLine($"Handshake respins, certificat invalid: {ex.Message}");
    return;
}

Console.WriteLine($"Protocol:     {ssl.SslProtocol}");
Console.WriteLine($"Cipher suite: {ssl.NegotiatedCipherSuite}");
Console.WriteLine($"Certificat:   {ssl.RemoteCertificate?.Subject}");
Console.WriteLine($"Emitent:      {ssl.RemoteCertificate?.Issuer}");
Console.WriteLine($"Autentificat: {ssl.IsAuthenticated}, criptat: {ssl.IsEncrypted}, semnat: {ssl.IsSigned}");
