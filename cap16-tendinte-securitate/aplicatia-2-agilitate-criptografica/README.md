# Aplicația practică 2: Analizor de agilitate criptografică

**În carte:** capitolul 16, „Aplicații practice”, Aplicația practică 2, și secțiunea 16.3.

| Proiect | Pasul | Ce face |
|---|---|---|
| `AnalizorCripto/` | 1–3 | Inventarul algoritmilor criptografici dintr-un cod C# (clasificat CUANTIC, DEPRECIAT, ATENȚIE, INFO, SIGUR) |
| `PqcDemo/` | 4 | Exemplul din secțiunea 16.3: încapsulare ML-KEM-768 și semnătură ML-DSA-65 cu .NET 10 |

**Cerințe:** .NET 10 SDK (Anexa A). `PqcDemo` cere un sistem pe care .NET găsește ML-KEM (OpenSSL 3.5+ pe Linux, Windows recent);
altfel rulați-l în container, din directorul proiectului:

```bash
cd AnalizorCripto && dotnet run && dotnet run -- ../../aplicatia-1-scanner-iot/ScannerIoT
cd ../PqcDemo
docker run --rm -v "$PWD":/src -w /src mcr.microsoft.com/dotnet/sdk:10.0-alpine dotnet run
```

Ieșirile așteptate sunt în carte.
