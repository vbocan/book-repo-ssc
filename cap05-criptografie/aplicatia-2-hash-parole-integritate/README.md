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

În bash: `export MANIFEST_KEY=$(openssl rand -hex 32)` și căi cu `/`. Ieșirile așteptate sunt mai jos
(salt-urile și cheile sunt aleatoare, deci valorile Base64 și hexazecimale diferă; ieșirea părții A este deterministă).

## Rezultatul așteptat

### `Lab5HashA` (partea A), determinist

```
Hash 1: C33D83F35D1A0891B18656CA1081D9619097F82CD07D136F0FDFD293E8D942AB
Hash 2: 3074585847516AF4127D356C1648DBE63F46358D83E128CED97BA08E52492277
Biți diferiți: 128 din 256 (50.0%)
```

### `Lab5Pbkdf2` (partea B)

Prima linie este mereu aceeași; salt-urile și rezumatele PBKDF2 diferă la fiecare rulare.

```
SHA-256 simplu (NU folosiți): 231ECC7D178DA5F22983BC579599396D6C139A457987AE1EE0026D88432D6A72
Înregistrare stocată: $pbkdf2-sha256$600000$fzZ8/GCQED5jms2EILv6dw==$dTTSF6HEzbbhWeRVJCSoaS4QXUYyeQ01qR7I5lNxoow=
Parola corectă acceptată: True
Parola greșită acceptată: False
A doua înregistrare:  $pbkdf2-sha256$600000$3LhvpIoJLtRrStpAUrH90A==$q2p0cbF9xScbOMjUmT3vEp0RjIjR1Wk69HTD2u7a5dU=
Înregistrările sunt identice: False
```

### `Lab5Argon2` (partea C)

Salt-ul, rezumatul și timpul diferă de la o rulare și de la un calculator la altul.

```
Înregistrare Argon2id: $argon2id$v=19$m=19456,t=2,p=1$1f1SX6G+CCWep9ARO1ef2A$7CqweFY9CjA62MtVsJHFV6D0PXPR6OvvR/Dn5dsSnFk
Timp de calcul: 97 ms
Parola corectă acceptată: True
Parola greșită acceptată: False
```

### `Lab5Manifest` (partea D)

După `create`: `Manifest creat: 3 fișiere -> ..\manifest.json`. După un `verify` imediat: `Integritate OK: nicio modificare.`
După ce modificați `a.txt`, ștergeți `b.txt` și creați `sub\d.txt`:

```
[MODIFICAT] a.txt
[ȘTERS]     b.txt
[NOU]       sub/d.txt
3 modificări detectate.
```

După modificarea unui rezumat în `manifest.json`: `[ALERTĂ] Manifestul a fost modificat (HMAC invalid). Verificarea se oprește.`
