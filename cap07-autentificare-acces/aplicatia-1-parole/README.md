# Aplicația practică 1: Validarea și stocarea securizată a parolelor (Lab7Parole)

**În carte:** capitolul 7, „Aplicații practice”, Aplicația practică 1.

Politică de parole în spiritul NIST SP 800-63B, estimarea tăriei, verificarea contra unei liste de parole comune
și stocarea cu PBKDF2-HMAC-SHA256 (600.000 de iterații) și comparație în timp constant.

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`. Opțional, descărcați lista SecLists în acest director ca `common-passwords.txt`:

```bash
curl -L -o common-passwords.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
```

Cartea tipărește doar un fragment al ieșirii; ieșirea completă, fără fișierul `common-passwords.txt`, este mai jos. Cu lista SecLists, prima linie devine `Lista de parole: common-passwords.txt`, urmată de numărul de parole încărcate (aproximativ 10.000).

## Rezultatul așteptat

Fără fișierul `common-passwords.txt` (salt-urile și hash-urile diferă la fiecare rulare, fiind aleatorii; aici sunt prescurtate):

```
Fișierul cu parole comune lipsește; se folosește lista încorporată.
Încărcate 22 de parole comune.

Parola: 'password' (compromisă; mod: factor unic)
  Valid: False: Parola apare în lista de parole compromise.
  Entropie naivă estimată: 37.6 biți

Parola: 'abc' (prea scurtă; mod: factor unic)
  Valid: False: Parola trebuie să aibă cel puțin 15 caractere (are 3).
  Entropie naivă estimată: 14.1 biți

Parola: 'ababababababababab' (repetitivă; mod: factor unic)
  Valid: False: Parola conține un tipar repetitiv.
  Entropie naivă estimată: 84.6 biți

Parola: 'munte-lac-2026' (14 caractere, factor unic; mod: factor unic)
  Valid: False: Parola trebuie să aibă cel puțin 15 caractere (are 14).
  Entropie naivă estimată: 85.2 biți

Parola: 'munte-lac-2026' (aceeași parolă, în MFA; mod: MFA)
  Valid: True: Parola îndeplinește cerințele.
  Entropie naivă estimată: 85.2 biți
  Hash: 600000:0EhbJwan...sw==:KPJY3DiW...5Ic=
  Verificare: True

Parola: 'CorectHorseBattery' (passphrase de 18 caractere; mod: factor unic)
  Valid: True: Parola îndeplinește cerințele.
  Entropie naivă estimată: 102.6 biți
  Hash: 600000:/oOQ5Uxh...Tg==:tO9xo0JP...0Zo=
  Verificare: True

Parola: 'xK9#mP2$vL5@nQ8' (aleatoare, 15 caractere; mod: factor unic)
  Valid: True: Parola îndeplinește cerințele.
  Entropie naivă estimată: 98.3 biți
  Hash: 600000:WbFItlZl...7Q==:fi9oQioz...Z/I=
  Verificare: True
```
