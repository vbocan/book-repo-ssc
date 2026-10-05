# Aplicația practică 1: Criptarea simetrică cu AES

**În carte:** capitolul 5, „Aplicații practice”, Aplicația practică 1.

Două proiecte consolă, fără pachete NuGet:

| Proiect | Partea din carte | Ce face |
|---|---|---|
| `Lab5Aes/` | A și B (același `Program.cs`) | Criptează `mesaj.txt` cu AES-256 în modurile ECB și CBC, apoi arată de ce ECB dezvăluie blocurile identice |
| `Lab5Gcm/` | C | Criptare autentificată AES-GCM și detectarea unui text cifrat modificat |

**Cerințe:** .NET 10 SDK (Anexa A).

**Rulare:**

```bash
cd Lab5Aes && dotnet run
cd ../Lab5Gcm && dotnet run
```

La prima rulare, `Lab5Aes` creează fișierul `mesaj.txt` și scrie `mesaj.ecb` și `mesaj.cbc` în directorul proiectului.
Cheile, IV-urile și nonce-urile sunt aleatoare, deci valorile Base64 și hexazecimale diferă de la o rulare la alta;
restul ieșirii este cel de mai jos. Cartea tipărește doar blocurile cifrate din partea B.

## Rezultatul așteptat

### `Lab5Aes` (părțile A și B)

```
Fișier citit: mesaj.txt (57 octeți)
ECB criptat (64 octeți): 6ydZG+SC6ZxM+ILf76sLOsH+HRFeX+tkSVAkxSuSZLG6zPVwA3BcNlwSrk6MLnsHfZMwGb+hbl8+BK/a85IC6A==
CBC criptat (64 octeți): HEUmH6+0kJ/Qgkwcy16/67hid99T0wmVt4FEM9CVyqFTtX9E6ErKlgyY15QTI8fDNOOH2RVFlKQtY0AxGVfbNg==
ECB decriptat: Acesta este un mesaj confidențial care trebuie protejat.
CBC decriptat: Acesta este un mesaj confidențial care trebuie protejat.
Identic cu originalul: True
ECB - blocurile cifrate:
  Bloc 0: C985E2F83591FA3E827342E7EEA407D7
  Bloc 1: C985E2F83591FA3E827342E7EEA407D7
  Bloc 2: C985E2F83591FA3E827342E7EEA407D7
  Bloc 3: F21A18EDB2B373D723E90FC31BB9F110
CBC - blocurile cifrate:
  Bloc 0: CBE3A3007142816D6B90B1F9747E43BB
  Bloc 1: 52CFD8A0219FFAE3FDA3F5A245B6C967
  Bloc 2: 92BEF765A8070BAC5FB6AF3137BD3947
  Bloc 3: 6CB43D62F25F311D4ADF1E1D43E5A6F3
```

Textul are 56 de caractere, dar 57 de octeți („ț” ocupă doi octeți în UTF-8); padding-ul PKCS#7 completează
până la 64 de octeți. În partea B, blocurile 0–2 sunt identice în ECB, iar blocul 3 este padding-ul PKCS#7.

### `Lab5Gcm` (partea C)

```
Nonce: 688F76BB6A11536BE7AEF586
Ciphertext: 5A284CB9D7B81F2F0D1F748DFFAD5B49C7881CDD92EF032F1B2A3E4FD7B179891DF3629AC8B0D5AEBFB9EFBDEF3FBE46935BAFAFD702166806BD
Tag: F7677CE2F69FA5614C4E370D379F7F27
Decriptat: Transfer: 50000 EUR către contul RO49AAAA1B31007593840000
Manipulare detectată! Tag-ul de autentificare nu se potrivește.
```
