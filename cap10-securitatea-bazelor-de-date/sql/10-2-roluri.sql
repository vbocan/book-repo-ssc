-- Roluri de bază de date
-- Carte: secțiunea 10.2, Roluri de bază de date (10-securitatea-bazelor-de-date.md:138–153).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date, tabelele, schema rapoarte și utilizatorii ioana și mihai ----
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
GO
CREATE SCHEMA rapoarte;
GO
CREATE USER ioana WITHOUT LOGIN;
CREATE USER mihai WITHOUT LOGIN;
GO

-- ---- Codul din carte ----
-- Crearea rolurilor
CREATE ROLE CititorRapoarte;
CREATE ROLE EditorComenzi;
CREATE ROLE AdminProduse;

-- Atribuirea permisiunilor rolurilor
GRANT SELECT ON SCHEMA::rapoarte TO CititorRapoarte;
GRANT SELECT, INSERT, UPDATE ON dbo.Comenzi TO EditorComenzi;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.Produse TO AdminProduse;

-- Adăugarea utilizatorilor în roluri
ALTER ROLE CititorRapoarte ADD MEMBER ioana;
ALTER ROLE CititorRapoarte ADD MEMBER mihai;
ALTER ROLE EditorComenzi ADD MEMBER ioana;

-- Ioana poate citi rapoartele și edita comenzile; Mihai poate doar citi rapoartele
GO

-- ---- Verificare (nu apare în carte) ----
SELECT r.name AS Rol, m.name AS Membru
FROM sys.database_role_members rm
JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
WHERE m.name IN (N'ioana', N'mihai')
ORDER BY Membru, Rol;
