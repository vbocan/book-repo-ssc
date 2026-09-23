# Aplicația practică 1: Validarea și stocarea securizată a parolelor (Lab7Parole)

**În carte:** capitolul 7, „Aplicații practice”, Aplicația practică 1.

Politică de parole în spiritul NIST SP 800-63B, estimarea tăriei, verificarea contra unei liste de parole comune
și stocarea cu PBKDF2-HMAC-SHA256 (600.000 de iterații) și comparație în timp constant.

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`. Opțional, descărcați lista SecLists în acest director ca `common-passwords.txt`:

```bash
curl -L -o common-passwords.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
```

Ieșirea așteptată (fără și cu listă) este în carte, după listing.
