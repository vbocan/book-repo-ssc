# Scripturi intenționat periculoase (capitolul 10)

**În carte:** capitolul 10, secțiunile 10.1 și 10.6.

> ⚠️ **Cod intenționat vulnerabil.** Folosiți-l doar pe calculatorul vostru, legat de `127.0.0.1`, pentru a înțelege atacul. Nu îl publicați pe internet și nu îl copiați în aplicații reale.

- `10-1-xp-cmdshell.sql`: ce poate face un atacator cu drepturi `sysadmin` pe un SQL Server **pentru Windows** (activează
  `xp_cmdshell` și execută o comandă a sistemului de operare). Pe containerul Linux al laboratorului `xp_cmdshell` nu există:
  `sp_configure` răspunde cu eroarea 15392, iar interogarea de verificare arată `value_in_use = 0`. Scriptul readuce la
  final configurația sigură.
- `10-6-payloaduri-sqli.txt`: interogările rezultate și payload-urile de SQL injection din 10.6 (bypass de autentificare,
  UNION, blind boolean și time-based, error-based). Nu este un script: payload-urile se introduc în programul
  vulnerabil din `../../aplicatia-1-sql-injection/vulnerabil/`.
