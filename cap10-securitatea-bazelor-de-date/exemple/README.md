# Exemple C# din secțiunile teoretice ale capitolului 10

**În carte:** capitolul 10, secțiunile 10.3, 10.4 și 10.6.

| Proiect | Secțiunea | Ce arată |
|---|---|---|
| `AlwaysEncrypted/` | 10.3, Always Encrypted | Interogare cu parametri tipizați pe coloane criptate (cere cheile CMK/CEK configurate în prealabil) |
| `CriptareTranzit/` | 10.3, Criptarea datelor în tranzit | `Encrypt=Strict` (TDS 8.0) și validarea certificatului serverului |
| `ClaseExemplu/` | 10.4 și 10.6 | Bibliotecă cu clasele `ContBancar` (concurență optimistă cu EF Core), `Autentificare` (interogări parametrizate + PBKDF2) și `InputValidator` |

Proiectele se compilează cu `dotnet build`. `AlwaysEncrypted` și `CriptareTranzit` au nevoie de un server configurat
ca în carte (certificat de încredere, chei Always Encrypted), deci nu rulează pe containerul de laborator fără pași suplimentari.
Fragmentele intenționat vulnerabile din 10.6 (login concatenat, `FromSqlRaw` cu interpolare, blacklist) rămân doar în carte.
