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
Cheile și IV-urile sunt aleatoare, deci valorile hexazecimale diferă de la o rulare la alta; restul ieșirii
este cel tipărit în carte după fiecare listing.
