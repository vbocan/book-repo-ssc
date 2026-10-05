-- Cum ajunge o interogare parametrizată la server (sp_executesql)
-- Carte: capitolul 10, secțiunea 10.5, Prevenirea SQL injection, 1. Interogări parametrizate.
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): tabelul Utilizatori; payload-ul nu găsește niciun rând ----
USE master;
GO
IF DB_ID(N'SSCCap10') IS NOT NULL
BEGIN
    ALTER DATABASE SSCCap10 SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE SSCCap10;
END;
GO
CREATE DATABASE SSCCap10;
GO
USE SSCCap10;
GO
CREATE TABLE dbo.Utilizatori (Username NVARCHAR(50) PRIMARY KEY, ParolaHash VARBINARY(32), Salt VARBINARY(16));
INSERT INTO dbo.Utilizatori VALUES (N'admin', 0x01, 0x02);
GO

-- ---- Codul din carte ----
exec sp_executesql N'SELECT ParolaHash, Salt FROM Utilizatori
    WHERE Username = @Username',
    N'@Username nvarchar(50)',
    @Username = N'admin'' --'
