-- Ce poate face un atacator cu drepturi sysadmin (xp_cmdshell, SQL Server pe Windows).
-- Pe SQL Server pentru Linux (containerul de laborator) xp_cmdshell nu există: sp_configure dă eroarea 15392
-- Carte: capitolul 10, secțiunea 10.1, Hardening-ul serverului de baze de date.
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Codul din carte ----
-- Ce poate face un atacator care a obținut drepturi sysadmin:
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';   -- rulează cu identitatea contului de serviciu SQL Server

-- Verificarea configurației (valoarea recomandată: 0 pentru toate)
SELECT name, value_in_use
FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'clr enabled',
               'Ole Automation Procedures', 'Database Mail XPs');
GO

-- ---- Revenire (nu apare în carte) ----
-- Readuce serverul la configurația sigură (xp_cmdshell dezactivat)
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
EXEC sp_configure 'show advanced options', 0;
RECONFIGURE;
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
