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

Cartea tipărește unele ieșiri scurtate; mai jos sunt ieșirile complete, obținute de autor pe 23.09.2026 (Linux, .NET 10). Datele de valabilitate, numerele de serie și uneori chiar tipul cheii se schimbă odată cu certificatele site-urilor, iar Google servește certificate diferite în funcție de client și de locație.

## Rezultatul așteptat

### `Lab6Cert`: `dotnet run` (activitatea 1a)

```
Subject: CN=www.google.com
Issuer: CN=WE2, O=Google Trust Services, C=US
Serial: 00E07C1AA47E6F638B0A82C43ECF7424E7
Valid from: 2026-09-10 to 2026-12-03 (84 zile)
Algorithm: sha256ECDSA
Key: ECDsaOpenSsl 256 biți
SAN: www.google.com
Extension: X509v3 Key Usage (2.5.29.15)
Extension: X509v3 Extended Key Usage (2.5.29.37)
Extension: X509v3 Basic Constraints (2.5.29.19)
Extension: X509v3 Subject Key Identifier (2.5.29.14)
Extension: X509v3 Authority Key Identifier (2.5.29.35)
Extension: Authority Information Access (1.3.6.1.5.5.7.1.1)
Extension: X509v3 Subject Alternative Name (2.5.29.17)
Extension: X509v3 Certificate Policies (2.5.29.32)
Extension: X509v3 CRL Distribution Points (2.5.29.31)
Extension: CT Precertificate SCTs (1.3.6.1.4.1.11129.2.4.2)

Lanț de certificare (3 niveluri):
  - CN=www.google.com
  - CN=WE2, O=Google Trust Services, C=US
  - CN=GTS Root R4, O=Google Trust Services LLC, C=US

Erori SSL: None
Răspuns HTTP: 200
```

### `openssl s_client -brief` (activitatea 2c)

```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=www.google.com
Hash used: SHA256
Signature type: ecdsa_secp256r1_sha256
Verification: OK
Negotiated TLS1.3 group: X25519MLKEM768
DONE
```

### testssl.sh pentru `www.google.com`, opțiunile `-p -f -S` (activitatea 3b, linii selectate)

```
 TLS 1.3    offered (OK): final
 KEMs offered                 MLKEM1024 X25519MLKEM768
 Elliptic curves offered:     prime256v1 X25519
 Server key size              EC 256 bits (curve P-256)
 Certificate Validity (UTC)   71 >= 60 days (2026-09-10 19:24 --> 2026-12-03 19:24)
 Certificate Revocation List  http://c.pki.goog/we2/dTM3-0hpWfE.crl
 OCSP URI                     --
 OCSP stapling                not offered
 Certificate Transparency     yes (certificate extension)
```
