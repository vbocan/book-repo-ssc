# Aplicația practică 1: Instrument de audit al securității fizice (PhysicalSecurityAudit)

**În carte:** capitolul 14, „Aplicații practice”, Aplicația practică 1.

Chestionar de audit pe categorii (D/N/P/X), scor global și pe categorii, recomandări prioritizate.
`raspunsuri.txt` conține răspunsurile de la activitatea 2, pentru un rezultat reproductibil.

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** interactiv cu `dotnet run`, sau reproductibil:

```bash
dotnet run < raspunsuri.txt
```

Raportul complet produs pe acest fișier este dat mai jos; data și ora sunt cele ale rulării. Cartea tipărește doar scorul global și scorurile pe categorii.

## Rezultatul așteptat

```
╔══════════════════════════════════════════════════╗
║        RAPORT DE AUDIT DE SECURITATE FIZICĂ      ║
╚══════════════════════════════════════════════════╝

  Organizație: ShopSecure SRL
  Auditor:     Ana Popescu
  Data:        2026-09-23 09:30

── SCOR GLOBAL ──

  62%: ACCEPTABIL

  [████████████████████████░░░░░░░░░░░░░░░░]

── SCORURI PE CATEGORII ──

  Sala de servere                 40% (Insuficient)
  Protecția mediului              50% (Acceptabil)
  Securitate perimetrală          60% (Acceptabil)
  Control acces                   70% (Acceptabil)
  Securitate clădire              75% (Bun)
  Securitate echipamente          80% (Bun)

── CONSTATĂRI CRITICE ──

  [CRITICAL] [S01] Accesul în sala de servere necesită autentificare multifactor?
             Categorie: Sala de servere
             Recomandare: Implementați MFA fizic: card + PIN sau card + biometrie.

  [CRITICAL] [S03] Există sistem de stingere a incendiilor adecvat sălii de servere (agent curat sau preacționare cu dublă interblocare)?
             Categorie: Sala de servere
             Recomandare: Instalați sistem de stingere cu agent curat (FK-5-1-12, gaz inert).

  [CRITICAL] [M02] Există sistem UPS funcțional și testat periodic?
             Categorie: Protecția mediului
             Recomandare: Instalați UPS dimensionat corespunzător și testați-l lunar.

  [HIGH    ] [P05] Perimetrul este monitorizat video 24/7?
             Categorie: Securitate perimetrală
             Recomandare: Instalați camere CCTV cu acoperire completă a perimetrului.

── STATISTICI ──

  Total întrebări:   30
  Conforme (Da):     16
  Neconforme (Nu):   9
  Parțial conforme:  4
  Nu se aplică:      1

  Referință: ISO/IEC 27001:2022, Anexa A, controalele 7.1–7.14 (controale fizice)
```
