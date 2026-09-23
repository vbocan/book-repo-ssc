# Exemple din secțiunile teoretice ale capitolului 9

**În carte:** capitolul 9, secțiunile 9.3 și 9.4.

| Proiect | Secțiunea | Ce arată |
|---|---|---|
| `RateLimiting/` | 9.3, Rate limiting | Limitarea ratei cererilor în ASP.NET Core (`AddRateLimiter`) |
| `CodificareIesiri/` | 9.4, Codificarea ieșirilor | Codificare HTML, JavaScript și URL pentru același input |
| `SesiuniAntiCsrf/` | 9.4, Managementul sesiunilor și protecția anti-CSRF | Cookie-uri de sesiune securizate și anti-forgery |

Fragmentele scurte de tip „GREȘIT/CORECT” din capitol (fail-open, validare, tratarea erorilor, secrete) nu sunt
programe complete și rămân doar în carte. **Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run` din fiecare director
(proiectele web ascultă implicit pe `http://localhost:5000`).
