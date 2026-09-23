# Aplicația practică 2: Funcții hash, parole și integritatea fișierelor

**În carte:** capitolul 5, „Aplicații practice”, Aplicația practică 2.

| Proiect | Partea | Ce face |
|---|---|---|
| `Lab5HashA/` | A | SHA-256 și efectul de avalanșă |
| `Lab5Pbkdf2/` | B | Stocarea parolelor cu PBKDF2, în formatul `$pbkdf2-sha256$...` |
| `Lab5Argon2/` | C | Aceeași pereche de funcții cu Argon2id (pachetul `Konscious.Security.Cryptography.Argon2` 1.3.1) |
| `Lab5Manifest/` | D | Manifest de integritate pentru un director, protejat prin HMAC-SHA256 |

Directorul `date/` conține cele trei fișiere de test de la partea D (`a.txt`, `b.txt`, `sub/c.txt`).

**Cerințe:** .NET 10 SDK (Anexa A); pentru partea C, acces la nuget.org.

**Rulare (părțile A–C):** `dotnet run` din directorul fiecărui proiect.

**Rulare (partea D), în PowerShell, din `Lab5Manifest/`:**

```powershell
$env:MANIFEST_KEY = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
dotnet run -- create ..\date ..\manifest.json
dotnet run -- verify ..\date ..\manifest.json
```

În bash: `export MANIFEST_KEY=$(openssl rand -hex 32)` și căi cu `/`. Ieșirile așteptate sunt în carte,
după fiecare listing (sărurile și cheile sunt aleatoare, deci valorile hexazecimale diferă).
