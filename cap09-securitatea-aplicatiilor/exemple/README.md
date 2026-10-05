# Exemple din secțiunile teoretice ale capitolului 9

**În carte:** capitolul 9, secțiunile 9.3 și 9.4.

| Proiect | Secțiunea | Ce arată |
|---|---|---|
| `RateLimiting/` | 9.3, Limitarea ratei | Limitarea ratei cererilor în ASP.NET Core (`AddRateLimiter`); cartea tipărește configurarea limitatorului și endpoint-ul protejat |
| `CodificareIesiri/` | 9.4, Codificarea ieșirilor | Codificare HTML, JavaScript și URL pentru același input; programul este descris în text, fără să fie tipărit |
| `SesiuniAntiCsrf/` | 9.4, Sesiunile și protecția anti-CSRF | Cookie-uri de sesiune securizate, headere de securitate și anti-forgery; cartea tipărește configurarea cookie-ului |

Fragmentele scurte de tip „GREȘIT/CORECT” din capitol (fail-open, validare, tratarea erorilor, secrete) nu sunt
programe complete și rămân doar în carte. **Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run` din fiecare director
(proiectele web ascultă implicit pe `http://localhost:5000`).
