# Aplicația practică 2: Integritatea probelor și lanțul de custodie (EvidenceCustody)

**În carte:** capitolul 13, „Aplicații practice”, Aplicația practică 2.

Hash-uri SHA-256 pentru probe și un jurnal de custodie înlănțuit (fiecare intrare conține hash-ul celei anterioare),
scris în `forensic-evidence-demo/` din directorul temporar. **Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`.

Hash-urile probelor sunt deterministe și trebuie să coincidă cu cele de mai jos; hash-urile intrărilor din jurnal
(`intrare: …`) depind de ora rulării și vor fi diferite. Cartea tipărește ieșirea scurtată, iar mai jos este ieșirea completă.

## Rezultatul așteptat

```
SIMULARE: GESTIONAREA PROBELOR DIGITALE

--- Pasul 1: Colectarea probelor ---

[+] Probă înregistrată: EVD-0001
    Fișier:      disk-image-001.raw
    Dimensiune:  137 bytes
    SHA-256:     6ab395c1e5521d5b08f0848a578f215d943638c4a30a98b6bacd271e89c5143f
    Colectat de: Ana Popescu

[+] Probă înregistrată: EVD-0002
    Fișier:      memory-dump-001.mem
    Dimensiune:  113 bytes
    SHA-256:     94d077baa54748653bdfbf8476f688cfc3d0997de179c37fa4d8672b1f82ab79
    Colectat de: Ana Popescu

--- Pasul 2: Transferul custodiei ---

[>] Transfer EVD-0001: Ana Popescu -> Mihai Ionescu (OK)

[X] Transfer EVD-0002 REFUZAT: Mihai Ionescu nu este custodele curent (Ana Popescu)

--- Pasul 3: Simularea alterării unei probe ---

[!] Fișierul memory-dump-001.mem a fost modificat.

--- Pasul 4: Reverificarea integrității ---

[=] Verificare integritate: EVD-0001
    Hash la colectare: 6ab395c1e5521d5b…
    Hash curent:       6ab395c1e5521d5b…
    Status: VALID

[=] Verificare integritate: EVD-0002
    Hash la colectare: 94d077baa5474865…
    Hash curent:       fcdacc49ac031949…
    Status: COMPROMIS

[X] Transfer EVD-0002 REFUZAT: hash-ul probei diferă de cel de la colectare

════════════════════════════════════════════════════════════════
 LANȚ DE CUSTODIE: EVD-0002
 Imaginea memoriei RAM a serverului SRV-DB-01
════════════════════════════════════════════════════════════════
 #2  COLLECTED        Ana Popescu
     Imaginea memoriei RAM a serverului SRV-DB-01 (113 bytes)
     proba: 94d077baa5474865…  intrare: 7612c47caa6f46ee…
 #4  TRANSFER_REFUSED Mihai Ionescu -> Elena Stan
     Mihai Ionescu nu este custodele curent (Ana Popescu)
     proba: 94d077baa5474865…  intrare: af3d0cfcb12bf462…
 #6  INTEGRITY_CHECK  Ana Popescu
     ALERTĂ: hash diferit de cel de la colectare
     proba: fcdacc49ac031949…  intrare: c45e10dae127d2b6…
 #7  TRANSFER_REFUSED Ana Popescu -> Mihai Ionescu
     hash-ul probei diferă de cel de la colectare
     proba: fcdacc49ac031949…  intrare: b09daa575f672daf…
════════════════════════════════════════════════════════════════

--- Pasul 5: Exportul și verificarea jurnalului ---

[+] Jurnal exportat: custody-log.json (7 intrări)
Jurnal intact: True
```
