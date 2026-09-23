# Aplicația practică 3: Analizor de pachete IPv4 (Lab8Pachete)

**În carte:** capitolul 8, „Aplicații practice”, Aplicația practică 3.

Parsarea antetelor IPv4/TCP/UDP/ICMP, detectarea tiparelor de scanare și a protocoalelor în clar.

**Cerințe:** .NET 10 SDK (Anexa A); Wireshark sau `tcpdump` pentru capturi pcap (Anexa B).

**Rulare:**

```bash
dotnet run -- --demo            # pachete sintetice, orice SO
dotnet run -- captura.pcap      # fișier pcap (nu pcapng)
dotnet run -- --live <adresă>   # doar Windows, ca Administrator
```

Ieșirea pentru `--demo` este deterministă și coincide cu cea din carte.
