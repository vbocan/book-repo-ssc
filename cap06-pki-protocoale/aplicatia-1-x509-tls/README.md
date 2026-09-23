# Aplicația practică 1: Certificate X.509 și TLS

**În carte:** capitolul 6, „Aplicații practice”, Aplicația practică 1.

| Proiect | Activitatea | Ce face |
|---|---|---|
| `Lab6Cert/` | 1 | Afișează lanțul de certificate și extensiile certificatului unui site HTTPS |
| `Lab6Tls/` | 2 | Negociază TLS cu `SslStream` și afișează protocolul și suita criptografică |

**Cerințe:** .NET 10 SDK (Anexa A), acces la internet (portul 443); pentru comparație, OpenSSL 3.5+ (Git Bash, Linux, macOS).

**Rulare:**

```bash
cd Lab6Cert && dotnet run
dotnet run -- https://expired.badssl.com
cd ../Lab6Tls && dotnet run
dotnet run -- expired.badssl.com
```

Ieșirile așteptate sunt în carte. Datele de valabilitate și numerele de serie se schimbă odată cu certificatele site-urilor.
