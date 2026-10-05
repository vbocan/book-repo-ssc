# Aplicația practică 2: Analizor de agilitate criptografică

**În carte:** capitolul 16, „Aplicații practice”, Aplicația practică 2, și secțiunea 16.3.

| Proiect | Pasul | Ce face |
|---|---|---|
| `AnalizorCripto/` | 1, 2, 4 | Inventarul algoritmilor criptografici dintr-un cod C# (clasificat CUANTIC, DEPRECIAT, ATENȚIE, INFO, SIGUR) |
| `PqcDemo/` | 3 | Exemplul din secțiunea 16.3: încapsulare ML-KEM-768 și semnătură ML-DSA-65 cu .NET 10 |

**Cerințe:** .NET 10 SDK (Anexa A). `PqcDemo` cere un sistem pe care .NET găsește ML-KEM (OpenSSL 3.5+ pe Linux, Windows recent);
altfel rulați-l în container, din directorul proiectului:

```bash
cd AnalizorCripto && dotnet run && dotnet run -- ../../aplicatia-1-scanner-iot/ScannerIoT
cd ../PqcDemo
docker run --rm -v "$PWD":/src -w /src mcr.microsoft.com/dotnet/sdk:10.0-alpine dotnet run
```

Ieșirea `PqcDemo` este tipărită integral în secțiunea 16.3. Cartea tipărește ieșirea analizorului scurtată (trei dintre cele 10 detecții); mai jos este ieșirea completă.

## Rezultatul așteptat

`dotnet run` din `AnalizorCripto/`, fără argumente, afișează:

```
=== ANALIZOR DE AGILITATE CRIPTOGRAFICĂ ===
Total detecții: 10
  [CUANTIC]    2
  [DEPRECIAT]  5
  [ATENȚIE]    1
  [INFO]       1
  [SIGUR]      1

[CUANTIC] RSA (ServiciuCripto.cs:44)
  Cod:  using var rsa = RSA.Create(3072);
  De ce: Spart de algoritmul lui Shor, indiferent de lungimea cheii.
  Fix:  ML-KEM (FIPS 203) sau ML-DSA (FIPS 204), eventual hibrid.

[CUANTIC] ECDSA/ECDH (ServiciuCripto.cs:52)
  Cod:  using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
  De ce: Spart de algoritmul lui Shor, ca și RSA.
  Fix:  ML-DSA pentru semnături, ML-KEM pentru schimbul de chei.

[DEPRECIAT] MD5 (ServiciuCripto.cs:7)
  Cod:  Convert.ToHexString(MD5.HashData(
  De ce: Coliziuni practice din 2004.
  Fix:  SHA-256 sau SHA-3; pentru parole, Argon2id sau PBKDF2.

[DEPRECIAT] SHA-1 (ServiciuCripto.cs:11)
  Cod:  public byte[] Checksum(byte[] date) => SHA1.HashData(date);
  De ce: Coliziune practică din 2017 (SHAttered). HMAC-SHA1 nu este vizat de regulă: nu e spart și apare legitim în TOTP.
  Fix:  SHA-256 sau SHA-3.

[DEPRECIAT] DES (ServiciuCripto.cs:19)
  Cod:  using var des = DES.Create();
  De ce: Cheie de 56 de biți, spartă prin forță brută din 1998.
  Fix:  AES-GCM.

[DEPRECIAT] Modul ECB (ServiciuCripto.cs:21)
  Cod:  des.Mode = CipherMode.ECB;
  De ce: Blocuri identice de text clar dau blocuri identice de text cifrat.
  Fix:  AES-GCM (criptare autentificată).

[DEPRECIAT] Criptare RSA PKCS#1 v1.5 (ServiciuCripto.cs:36)
  Cod:  rsa.Encrypt(cheie, RSAEncryptionPadding.Pkcs1);
  De ce: Vulnerabilă la atacuri de tip padding oracle (Bleichenbacher 1998, ROBOT 2017).
  Fix:  RSAEncryptionPadding.OaepSHA256 sau, mai bine, ML-KEM.

[ATENȚIE] Semnătură RSA PKCS#1 v1.5 (ServiciuCripto.cs:46)
  Cod:  return rsa.SignData(document, sha, RSASignaturePadding.Pkcs1);
  De ce: Permisă de FIPS 186-5; atacurile Bleichenbacher vizează criptarea, nu semnătura.
  Fix:  RSASignaturePadding.Pss pentru sisteme noi.

[INFO] AES-128 (ServiciuCripto.cs:30)
  Cod:  aes.KeySize = 128;
  De ce: Acceptat de NIST și în era post-cuantică (categoria 1).
  Fix:  AES-256 pentru date cu viață lungă; obligatoriu în CNSA 2.0.

[SIGUR] Algoritm post-cuantic (ServiciuCripto.cs:59)
  Cod:  using var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
  De ce: Standardizat de NIST în FIPS 203/204/205.
  Fix:  Verificați MLKem.IsSupported înainte de utilizare.

[ACȚIUNE IMEDIATĂ] Algoritmi depreciați, de înlocuit indiferent de amenințarea cuantică.
[PLANIFICARE] Algoritmi vulnerabili cuantic: includeți-i în inventarul criptografic și în planul de migrare (NIST IR 8547, proiect: RSA-2048 și echivalentele depreciate după 2030, toți interziși după 2035).
```
