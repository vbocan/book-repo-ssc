# Aplicația practică 3: Analizor de loguri pentru detecția incidentelor (AuthLogAnalyzer)

**În carte:** capitolul 13, „Aplicații practice”, Aplicația practică 3.

Detectează forța brută (inclusiv cea reușită), escaladarea privilegiilor de pe un cont compromis și accesul anomal
(oră neobișnuită, IP necunoscut, weekend) într-un log de autentificare în UTC. **Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`.

Ieșirea este deterministă; cartea tipărește doar sumarul și primele trei alerte, iar mai jos este ieșirea completă.

## Rezultatul așteptat

```
ANALIZOR DE LOGURI DE SECURITATE

[+] 23 evenimente încărcate din auth-events.log

═════════════════════════════════════════════════════════════════
 RAPORT DE ANALIZĂ A LOGURILOR DE SECURITATE
═════════════════════════════════════════════════════════════════
 Total evenimente analizate: 23
 Alerte generate: 7
   CRITICAL: 3
   HIGH:     2
   MEDIUM:   2
═════════════════════════════════════════════════════════════════

 [!!!] Alerta #1: BRUTE_FORCE (CRITICAL)
       Brute force REUȘIT: 7 eșecuri pentru admin de la
       192.168.50.99
         2024-01-15 23:01:05 UTC LOGIN_FAILURE user=admin
         2024-01-15 23:01:08 UTC LOGIN_FAILURE user=admin
         ... și alte 6 evenimente

 [!!!] Alerta #2: PRIVILEGE_ESCALATION (CRITICAL)
       [CONT COMPROMIS] Modificare privilegii de admin de la
       192.168.50.99: role=Domain Admins added for backdoor_user
         2024-01-15 23:05:00 UTC PRIVILEGE_CHANGE user=admin

 [!!!] Alerta #3: PRIVILEGE_ESCALATION (CRITICAL)
       [CONT COMPROMIS] Cont creat de admin de la 192.168.50.99:
       new_account=backdoor_user
         2024-01-15 23:06:12 UTC ACCOUNT_CREATED user=admin

 [!! ] Alerta #4: ANOMALOUS_ACCESS (HIGH)
       Acces anomal: maria.pop de la 203.0.113.55: ora
       neobișnuită (02:30), IP necunoscut (203.0.113.55), acces
       în weekend
         2024-01-20 02:30:00 UTC LOGIN_SUCCESS user=maria.pop

 [!! ] Alerta #5: ANOMALOUS_ACCESS (HIGH)
       Acces anomal: ion.radu de la 198.51.100.33: ora
       neobișnuită (02:45), IP necunoscut (198.51.100.33), acces
       în weekend
         2024-01-20 02:45:00 UTC LOGIN_SUCCESS user=ion.radu

 [!  ] Alerta #6: ANOMALOUS_ACCESS (MEDIUM)
       Acces anomal: admin de la 192.168.50.99: ora neobișnuită
       (23:02)
         2024-01-15 23:02:45 UTC LOGIN_SUCCESS user=admin

 [!  ] Alerta #7: PRIVILEGE_ESCALATION (MEDIUM)
       Modificare privilegii de sysadmin de la 10.0.1.5:
       role=DB_Read added for elena.stan
         2024-01-16 10:00:00 UTC PRIVILEGE_CHANGE user=sysadmin
```
