# Aplicația practică 1: Scanner de securitate IoT pe un laborator simulat

**În carte:** capitolul 16, „Aplicații practice”, Aplicația practică 1.

> ⚠️ `laborator-iot/docker-compose.yml` pornește servicii **intenționat nesigure** (Telnet, panou web cu `admin:admin`,
> broker MQTT anonim), toate legate doar de `127.0.0.1`. Nu le expuneți în rețea. `ScannerIoT` refuză implicit orice
> adresă care nu este locală; scanarea unor sisteme fără autorizare scrisă este ilegală (capitolul 15, Codul penal art. 360–366).

**Cerințe:** Docker (Anexa C), .NET 10 SDK (Anexa A).

**Rulare:**

```bash
cd laborator-iot && docker compose up -d && docker compose ps
cd ../ScannerIoT && dotnet run
cd ../laborator-iot && docker compose down
```

Ieșirea așteptată, cu laboratorul pornit, este în carte. Remedierea de la pasul 5 se face în `docker-compose.yml`.
