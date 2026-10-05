-- Modelul GRANT/REVOKE/DENY
-- Carte: capitolul 10, secțiunea 10.2, Modelul GRANT/REVOKE/DENY.
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date, tabelele și utilizatorii folosiți în exemplu ----
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
CREATE TABLE dbo.Comenzi (ComandaId INT PRIMARY KEY IDENTITY, Produs NVARCHAR(100));
CREATE TABLE dbo.Produse (ProdusId INT PRIMARY KEY IDENTITY, Denumire NVARCHAR(200));
CREATE TABLE dbo.Clienti (ClientId INT PRIMARY KEY IDENTITY, Nume NVARCHAR(100));
CREATE USER UtilizatorRapoarte WITHOUT LOGIN;
CREATE USER ContAplicatie WITHOUT LOGIN;
GO

-- ---- Codul din carte ----
-- Acordarea permisiunii de citire pe un tabel
GRANT SELECT ON dbo.Comenzi TO UtilizatorRapoarte;

-- Acordarea permisiunilor de citire și scriere
GRANT SELECT, INSERT, UPDATE ON dbo.Produse TO ContAplicatie;

-- Retragerea unei permisiuni acordate anterior
REVOKE DELETE ON dbo.Comenzi FROM ContAplicatie;

-- Interzicerea explicită
DENY DELETE ON dbo.Clienti TO ContAplicatie;
GO

-- ---- Verificare (nu apare în carte) ----
SELECT USER_NAME(grantee_principal_id) AS Utilizator, OBJECT_NAME(major_id) AS Obiect,
       permission_name, state_desc
FROM sys.database_permissions
WHERE class = 1
ORDER BY Utilizator, Obiect;
