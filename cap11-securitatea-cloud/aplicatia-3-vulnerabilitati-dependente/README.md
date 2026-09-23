# Aplicația practică 3: Verificator de vulnerabilități pentru dependențe (VulnCheck)

**În carte:** capitolul 11, „Aplicații practice”, Aplicația practică 3.

Compară inventarul unei imagini de container cu o bază de vulnerabilități **inventate** (`DEMO-2026-0101`…`0107`) și
întoarce un cod de ieșire nenul când găsește vulnerabilități critice, ca într-un pipeline CI.
**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`, apoi `echo $?` (bash) sau `$LASTEXITCODE` (PowerShell): 1.
Ieșirea coincide cu cea din carte, cu excepția datei scanării.
