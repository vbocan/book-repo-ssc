-- Permisiuni pe coloane și Dynamic Data Masking
-- Carte: secțiunea 10.2, Permisiuni pe coloane și Dynamic Data Masking (10-securitatea-bazelor-de-date.md:234–253, 10-securitatea-bazelor-de-date.md:226–228).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date și utilizatorii; tabelul Clienti (al doilea bloc din carte) se creează înaintea GRANT-ului pe coloane (primul bloc) ----
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
CREATE USER SuportClienti WITHOUT LOGIN;
CREATE USER AdminConformitate WITHOUT LOGIN;
CREATE USER Marketing WITHOUT LOGIN;
GO

-- ---- Codul din carte ----
CREATE TABLE dbo.Clienti
(
    ClientId    INT PRIMARY KEY IDENTITY,
    Nume        NVARCHAR(100),
    Email       NVARCHAR(100) MASKED WITH (FUNCTION = 'email()'),
    CNP         CHAR(13) MASKED WITH (FUNCTION = 'partial(1, "XXXXXXXXXX", 2)'),
    NrCard      CHAR(16) MASKED WITH (FUNCTION = 'partial(0, "XXXXXXXXXXXX", 4)'),
    Telefon     NVARCHAR(15) MASKED WITH (FUNCTION = 'default()')
);

-- Un utilizator fără UNMASK vede, pentru un client cu datele complete:
-- Email:   aXXX@XXXX.com
-- CNP:     2XXXXXXXXXX85
-- NrCard:  XXXXXXXXXXXX7890
-- Telefon: xxxx

-- Dreptul de a vedea datele nemascate (din SQL Server 2022 se poate acorda
-- și granular, pe schemă, tabel sau coloană)
GRANT UNMASK TO AdminConformitate;
GRANT UNMASK ON dbo.Clienti(Email) TO Marketing;

-- Acces doar la coloanele necesare
GRANT SELECT ON dbo.Clienti (ClientId, Nume, Email) TO SuportClienti;
-- SuportClienti nu poate citi coloanele CNP și NrCard
GO

-- ---- Verificare (nu apare în carte) ----
INSERT INTO dbo.Clienti (Nume, Email, CNP, NrCard, Telefon)
VALUES (N'Ana Popescu', N'ana.popescu@exemplu.ro', '2850415123485', '4111222233337890', N'0722123456');
GRANT SELECT ON dbo.Clienti TO Marketing;
GO
EXECUTE AS USER = 'SuportClienti';
SELECT ClientId, Nume, Email FROM dbo.Clienti;   -- Email mascat: aXXX@XXXX.com
REVERT;
EXECUTE AS USER = 'Marketing';
SELECT Email, CNP, NrCard, Telefon FROM dbo.Clienti;   -- Email nemascat, restul mascate
REVERT;
