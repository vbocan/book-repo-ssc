-- View-uri ca mecanism de securitate
-- Carte: secțiunea 10.2, View-uri ca mecanism de securitate (10-securitatea-bazelor-de-date.md:265–273).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date, tabelul Clienti și utilizatorul SuportClienti ----
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
CREATE TABLE dbo.Clienti (ClientId INT PRIMARY KEY IDENTITY, Nume NVARCHAR(100),
    Email NVARCHAR(100), CNP CHAR(13));
INSERT INTO dbo.Clienti (Nume, Email, CNP) VALUES (N'Ana Popescu', N'ana@exemplu.ro', '2850415123485');
CREATE USER SuportClienti WITHOUT LOGIN;
GO

-- ---- Codul din carte ----
-- View care expune doar datele nesensibile
CREATE VIEW dbo.ClientiPublic AS
SELECT ClientId, Nume, Email
FROM dbo.Clienti;
GO

-- Utilizatorii de suport au acces doar la view, nu și la tabelul de bază
GRANT SELECT ON dbo.ClientiPublic TO SuportClienti;
DENY SELECT ON dbo.Clienti TO SuportClienti;
GO

-- ---- Verificare (nu apare în carte) ----
EXECUTE AS USER = 'SuportClienti';
SELECT * FROM dbo.ClientiPublic;          -- permis
BEGIN TRY
    SELECT CNP FROM dbo.Clienti;           -- refuzat
END TRY
BEGIN CATCH
    PRINT ERROR_MESSAGE();
END CATCH;
REVERT;
