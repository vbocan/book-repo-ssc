# Aplicația practică 3: Criptografia cu chei publice

**În carte:** capitolul 5, „Aplicații practice”, Aplicația practică 3.

| Proiect | Partea | Ce face |
|---|---|---|
| `Lab5RsaA/` | A | Generarea cheilor RSA, export PEM, criptare RSA-OAEP și limita de dimensiune a mesajului |
| `Lab5RsaB/` | B | Criptare hibridă prin transportul cheii (RSA-OAEP + AES-GCM) |
| `Lab5Ecdh/` | C | Acord de chei ECDH pe P-256 + AES-GCM |

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run` din directorul fiecărui proiect. Ieșirea așteptată este mai jos;
cheile și textele cifrate diferă la fiecare rulare.

## Rezultatul așteptat

### `Lab5RsaA` (partea A)

Mesajul excepției depinde de sistemul de operare: cel de mai jos provine de la OpenSSL, pe Linux, iar pe Windows textul este altul.

```
=== Cheie publică ===
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnh0gActqryTQyvGBbBB
jGHxUSJg...

Mesaj criptat (256 octeți): CiVsSMJik0IzHZ2kNByuF5uVLn/dAudC2sS0zcJb2rKc7msg79my7+zkZ9G8...
Mesaj decriptat: Cheie de sesiune: AES-256-GCM-KEY-abc123def456

Eroare la mesaj prea mare: error:0200006E:rsa routines::data too large for key size
Soluție: folosiți criptarea hibridă (RSA + AES)!
```

### `Lab5RsaB` (partea B)

```
Mesaj original: 10000 octeți
Cheie criptată RSA: 256 octeți
Mesaj criptat AES: 10000 octeți
Decriptare corectă: True
```

### `Lab5Ecdh` (partea C)

Cheia comună diferă la fiecare rulare, dar este aceeași pentru Alice și Bob.

```
Cheia calculată de Alice: 31BF2B3E4BFB051DD7E0EA8151FED241FE9508515AAAB7E94AE4DBCC88E67395
Cheia calculată de Bob:   31BF2B3E4BFB051DD7E0EA8151FED241FE9508515AAAB7E94AE4DBCC88E67395
Chei identice: True
Bob a decriptat: Mesaj protejat cu o cheie obținută prin ECDH
```
