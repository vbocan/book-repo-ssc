# Aplicația practică 2: Generator și validator TOTP (Lab7Totp)

**În carte:** capitolul 7, „Aplicații practice”, Aplicația practică 2.

Implementarea TOTP (RFC 6238) cu HMAC-SHA1, verificată cu vectorul de test din RFC (`287082` pentru T = 59 s),
generarea secretului Base32, URI-ul `otpauth://` și validarea cu fereastră de toleranță.

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`. Secretul și codurile se schimbă la fiecare rulare; rezultatele
validării și vectorul de test coincid cu ieșirea din carte.
