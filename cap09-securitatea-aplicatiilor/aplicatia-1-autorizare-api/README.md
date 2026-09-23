# Aplicația practică 1: autorizarea la nivel de obiect și de proprietate într-un API

**În carte:** capitolul 9, „Aplicații practice”, Aplicația practică 1.

> ⚠️ **Cod intenționat vulnerabil.** Folosiți-l doar pe calculatorul vostru, legat de `127.0.0.1`, pentru a înțelege atacul. Nu îl publicați pe internet și nu îl copiați în aplicații reale.

Proiectul `vulnerabil/` (LabAutorizare, ASP.NET Core minimal API) expune aceleași operații de două ori: sub `/v1`
**vulnerabil** la BOLA/IDOR și la mass assignment (BOPLA), sub `/v2` corectat. Autentificarea este simulată prin
header-ul `X-Utilizator`. `appsettings.json` leagă serverul de `http://127.0.0.1:5000`.

**Cerințe:** .NET 10 SDK (Anexa A), `curl` (în PowerShell: `curl.exe`).

**Rulare:**

```bash
cd vulnerabil
dotnet run --urls http://localhost:5000
```

Într-un al doilea terminal:

```bash
curl -i http://localhost:5000/v1/comenzi/2 -H "X-Utilizator: ana"
curl -i http://localhost:5000/v2/comenzi/2 -H "X-Utilizator: ana"
curl -i http://localhost:5000/v2/comenzi/1 -H "X-Utilizator: ana"
curl -X PUT http://localhost:5000/v1/profil -H "X-Utilizator: ion" -H "Content-Type: application/json" -d "{\"username\":\"ion\",\"numeComplet\":\"Ion Ionescu\",\"rol\":\"administrator\"}"
curl -X PUT http://localhost:5000/v2/profil -H "X-Utilizator: ana" -H "Content-Type: application/json" -d "{\"numeComplet\":\"Ana Popescu\",\"rol\":\"administrator\"}"
```

Răspunsurile așteptate sunt în carte.
