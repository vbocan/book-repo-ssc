-- Privilegii minime pentru contul aplicației
-- Carte: secțiunea 10.6, Prevenirea SQL injection, 5. Privilegii minime (10-securitatea-bazelor-de-date.md:1210–1225, 10-securitatea-bazelor-de-date.md:1231–1232).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza AppDB cu tabelele din exemplu; login-ul se recreează la fiecare rulare ----
USE master;
GO
IF DB_ID(N'AppDB') IS NOT NULL
BEGIN
    ALTER DATABASE AppDB SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE AppDB;
END;
IF SUSER_ID(N'AppWebLogin') IS NOT NULL DROP LOGIN AppWebLogin;
GO
CREATE DATABASE AppDB;
GO
USE AppDB;
CREATE TABLE dbo.Produse (ProdusId INT PRIMARY KEY);
CREATE TABLE dbo.Categorii (CategorieId INT PRIMARY KEY);
CREATE TABLE dbo.Comenzi (ComandaId INT PRIMARY KEY);
CREATE TABLE dbo.Utilizatori (UtilizatorId INT PRIMARY KEY);
GO
USE master;
GO

-- ---- Codul din carte ----
-- Login-ul (nivel de server) și utilizatorul (nivel de bază de date).
-- CREATE LOGIN ... WITH PASSWORD cere autentificare mixtă activată.
CREATE LOGIN AppWebLogin WITH PASSWORD = N'P@rola_Compl3xa!';
GO
USE AppDB;
CREATE USER AppWebUser FOR LOGIN AppWebLogin;

-- Doar SELECT pe tabelele necesare
GRANT SELECT ON dbo.Produse TO AppWebUser;
GRANT SELECT ON dbo.Categorii TO AppWebUser;

-- INSERT/UPDATE doar pe tabelul de comenzi
GRANT INSERT, UPDATE ON dbo.Comenzi TO AppWebUser;

-- Nicio permisiune pe tabelele sensibile (Utilizatori, DateFinanciare etc.):
-- pur și simplu nu i se acordă, iar contul nu face parte din niciun rol care le-ar da.
GO

USE master;
DENY VIEW ANY DATABASE TO AppWebLogin;
GO

-- ---- Verificare (nu apare în carte) ----
EXECUTE AS LOGIN = N'AppWebLogin';
USE AppDB;
SELECT COUNT(*) AS Produse FROM dbo.Produse;    -- permis
BEGIN TRY
    SELECT COUNT(*) FROM dbo.Utilizatori;         -- refuzat
END TRY
BEGIN CATCH
    PRINT ERROR_MESSAGE();
END CATCH;
USE master;
REVERT;
