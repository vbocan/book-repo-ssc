# Aplicația practică 2: Integritatea probelor și lanțul de custodie (EvidenceCustody)

**În carte:** capitolul 13, „Aplicații practice”, Aplicația practică 2.

Hash-uri SHA-256 pentru probe și un jurnal de custodie înlănțuit (fiecare intrare conține hash-ul celei anterioare),
scris în `forensic-evidence-demo/` din directorul temporar. **Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`.
Hash-urile probelor sunt deterministe și coincid cu cele din carte; hash-urile intrărilor depind de ora rulării.
