# Exemple C# din secțiunile teoretice ale capitolului 10

**În carte:** capitolul 10, secțiunile 10.1, 10.3 și 10.5.

| Proiect | Secțiunea | Ce arată |
|---|---|---|
| `AlwaysEncrypted/` | 10.3, Always Encrypted | Interogare cu parametri tipizați pe coloane criptate (cere cheile CMK/CEK configurate în prealabil) |
| `CriptareTranzit/` | 10.3, Conexiunea și cheile | `Encrypt=Strict` (TDS 8.0) și validarea certificatului serverului |
| `ClaseExemplu/` | 10.1 și 10.5 | Bibliotecă cu clasele `ContBancar` (concurență optimistă cu EF Core), `Autentificare` (interogări parametrizate + PBKDF2) și `InputValidator` |

Proiectele se compilează cu `dotnet build`. `AlwaysEncrypted` și `CriptareTranzit` au nevoie de un server configurat
ca în carte (certificat de încredere, chei Always Encrypted), deci nu rulează pe containerul de laborator fără pași suplimentari.
Fragmentele intenționat vulnerabile din 10.5 (login concatenat, `FromSqlRaw` cu interpolare, blacklist) sunt descrise doar în textul cărții; varianta tipărită a funcțiilor vulnerabile este cea din `../aplicatia-1-sql-injection/vulnerabil/`. În carte nu mai este tipărit decât fragmentul cu parametrii tipizați din `AlwaysEncrypted/`; celelalte proiecte sunt citate prin cale.
