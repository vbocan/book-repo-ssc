# Aplicația practică 2: Simulator de firewall stateless (Lab8Firewall)

**În carte:** capitolul 8, „Aplicații practice”, Aplicația practică 2.

Evaluarea pachetelor pe reguli ordonate (prima potrivire câștigă) și detectarea regulilor umbrite.
Setul de reguli conține **intenționat** două greșeli de ordonare, pe care le corectați ca exercițiu.

**Cerințe:** .NET 10 SDK (Anexa A). **Rulare:** `dotnet run`. Ieșirea este deterministă; cartea tipărește primele două blocuri, iar mai jos este ieșirea completă.

## Rezultatul așteptat

```
=== Evaluare pachete ===

Sursă              Dest               Port   Acțiune  Regulă  Motiv
------------------------------------------------------------------------------------------
203.0.113.50       192.168.1.10       443    PERMIT   #10     Permite HTTPS către serverul web
203.0.113.50       192.168.1.20       3306   DENY     #30     Blochează accesul extern la MySQL
192.168.1.5        192.168.1.20       3306   DENY     #30     Blochează accesul extern la MySQL
10.0.0.100         192.168.1.15       22     PERMIT   #50     Permite SSH de la rețeaua de management
203.0.113.50       192.168.1.10       22     DENY     #60     Deny implicit: blochează tot restul
172.16.0.5         192.168.1.10       8080   DENY     #60     Deny implicit: blochează tot restul

=== Analiza umbririi regulilor ===

[!] Regula 40 ("Permite accesul intern la MySQL") este ascunsă de regula 30 ("Blochează accesul extern la MySQL")
  CRITIC: acțiunile diferă! (DENY vs PERMIT)
[!] Regula 70 ("Permite accesul de monitoring") este ascunsă de regula 60 ("Deny implicit: blochează tot restul")
  CRITIC: acțiunile diferă! (DENY vs PERMIT)

=== Statistici ===
Pachete permise: 2/6
Pachete blocate: 4/6
```
