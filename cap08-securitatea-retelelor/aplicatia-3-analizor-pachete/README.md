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

Ieșirea pentru `--demo` este deterministă; cartea o tipărește scurtată, iar mai jos este ieșirea completă.

## Rezultatul așteptat pentru `--demo`

```
Mod demonstrativ: pachete sintetice

[1] TCP 192.168.1.23:51514 → 192.168.1.10:443 [SYN] (40 octeți, TTL 64)
[2] TCP 192.168.1.10:443 → 192.168.1.23:51514 [SYN,ACK] (40 octeți, TTL 64)
[3] UDP 192.168.1.23:53001 → 192.168.1.1:53 (28 octeți, TTL 64) → interogare DNS
[4] TCP 192.168.1.23:51515 → 192.168.1.10:23 [ACK,PSH] (40 octeți, TTL 64)
    → protocol necriptat: datele și parolele circulă în clar
[5] TCP 203.0.113.66:40000 → 192.168.1.10:80 [SYN,FIN] (40 octeți, TTL 64)
    → flag-uri invalide (SYN+FIN): posibilă scanare stealth
[6] TCP 203.0.113.66:40001 → 192.168.1.10:21 [SYN] (40 octeți, TTL 64)
[7] TCP 203.0.113.66:40001 → 192.168.1.10:22 [SYN] (40 octeți, TTL 64)
[8] TCP 203.0.113.66:40001 → 192.168.1.10:25 [SYN] (40 octeți, TTL 64)
[9] TCP 203.0.113.66:40001 → 192.168.1.10:53 [SYN] (40 octeți, TTL 64)
[10] TCP 203.0.113.66:40001 → 192.168.1.10:110 [SYN] (40 octeți, TTL 64)
[11] TCP 203.0.113.66:40001 → 192.168.1.10:135 [SYN] (40 octeți, TTL 64)
[12] TCP 203.0.113.66:40001 → 192.168.1.10:139 [SYN] (40 octeți, TTL 64)
[13] TCP 203.0.113.66:40001 → 192.168.1.10:143 [SYN] (40 octeți, TTL 64)
[14] TCP 203.0.113.66:40001 → 192.168.1.10:445 [SYN] (40 octeți, TTL 64)
[15] TCP 203.0.113.66:40001 → 192.168.1.10:3389 [SYN] (40 octeți, TTL 64)

=== Sumar: pachete IPv4 analizate = 15 ===
192.168.1.23: porturi distincte cu SYN = 1 → normal
203.0.113.66: porturi distincte cu SYN = 11 → POSIBILĂ SCANARE DE PORTURI
```
