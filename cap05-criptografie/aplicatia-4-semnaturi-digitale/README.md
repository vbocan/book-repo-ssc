# Aplicația practică 4: Semnături digitale

**În carte:** capitolul 5, „Aplicații practice”, Aplicația practică 4.

Cartea cere „câte un proiect de consolă pentru fiecare parte”, fără să le dea nume; aici se numesc:

| Proiect | Partea | Ce face |
|---|---|---|
| `Lab5RsaPss/` | A | Semnătură RSA-PSS și detectarea documentului modificat |
| `Lab5Ecdsa/` | B | Semnătură ECDSA P-256, formatele IEEE P1363 și DER |
| `Lab5Performanta/` | C | Compararea timpilor RSA-2048 și ECDSA P-256 la semnare și verificare |

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run` (partea C: `dotnet run -c Release`, cu celelalte aplicații grele închise).
Timpii din partea C depind de procesor; comparați ordinele de mărime cu cele din carte.
