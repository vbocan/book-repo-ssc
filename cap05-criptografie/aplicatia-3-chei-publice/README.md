# Aplicația practică 3: Criptografia cu chei publice

**În carte:** capitolul 5, „Aplicații practice”, Aplicația practică 3.

| Proiect | Partea | Ce face |
|---|---|---|
| `Lab5RsaA/` | A | Generarea cheilor RSA, export PEM, criptare RSA-OAEP și limita de dimensiune a mesajului |
| `Lab5RsaB/` | B | Criptare hibridă prin transportul cheii (RSA-OAEP + AES-GCM) |
| `Lab5Ecdh/` | C | Acord de chei ECDH pe P-256 + AES-GCM |

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run` din directorul fiecărui proiect. Ieșirea așteptată este în carte;
cheile și textele cifrate diferă la fiecare rulare.
