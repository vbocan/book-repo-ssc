# Aplicația practică 1: Verificator de conformitate GDPR (GdprComplianceChecker)

**În carte:** capitolul 15, „Aplicații practice”, Aplicația practică 1.

Evaluează profilul unei organizații fictive (ShopSecure SRL) contra unor reguli derivate din GDPR (consimțământ,
minimizarea datelor, criptare, retenție, notificarea încălcărilor, DPO, DPIA) și produce un raport cu recomandări.
**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`. Ieșirea este deterministă; cartea tipărește doar
verificările DPO și DPIA și bilanțul final, iar ieșirea completă este mai jos.

## Rezultatul așteptat

```
════════════════════════════════════════════════════════════
  Verificare de conformitate GDPR
  ShopSecure SRL — Platformă e-commerce
════════════════════════════════════════════════════════════

  [WARNING] Consimțământ: Calitatea consimțământului
            Consimțământ: retragerea nu este la fel de ușoară ca
            acordarea.
            -> Art. 7(3): retragerea trebuie să fie la fel de ușoară
               ca acordarea. Considerentul 43: granularitate per scop.

  [FAIL]    Minimizarea datelor: Câmpuri colectate vs. necesare
            4 câmpuri posibil nenecesare: data nașterii, gen, adresă
            IP, cookies preferințe.
            -> Art. 5(1)(c): datele trebuie să fie adecvate,
               relevante și limitate la ceea ce este necesar scopului
               prelucrării.

  [PASS]    Criptare: Protecția datelor personale
            Criptare la stocare și în tranzit cu AES-256 + TLS 1.3.

  [WARNING] Politica de retenție: Ștergere automată
            Retenție definită (365 de zile), dar fără ștergere
            automată.
            -> Implementați mecanisme automate de
               ștergere/anonimizare la expirarea perioadei de retenție.

  [PASS]    Notificarea breșelor: Procedură de notificare
            Procedură definită cu notificare în 48h.

  [FAIL]    DPO: Responsabil cu protecția datelor
            DPO obligatoriu (art. 37(1)): monitorizare sistematică
            pe scară largă.
            -> Desemnați un DPO (angajat sau extern) și comunicați
               datele de contact autorității (art. 37(7)).

  [WARNING] DPIA: Evaluarea impactului
            DPIA necesară, neefectuată: 3 criterii din ghidurile
            WP248 îndeplinite.
            -> Efectuați DPIA înainte de a începe prelucrarea (art.
               35); dacă riscul rămâne ridicat, art. 36.

────────────────────────────────────────────────────────────
  Total: 7 verificări | 2 PASS | 3 WARNING | 2 FAIL
  Scor de conformitate: 50%
  Verdict: Conformitate scăzută: riscuri semnificative
════════════════════════════════════════════════════════════
```
