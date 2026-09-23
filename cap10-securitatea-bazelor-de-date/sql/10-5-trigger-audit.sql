-- Trigger de audit pentru UPDATE
-- Carte: secțiunea 10.5, Trigger-e de audit pentru operații DML (10-securitatea-bazelor-de-date.md:674–713).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date și tabelul Clienti ----
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
CREATE TABLE dbo.Clienti (ClientId INT PRIMARY KEY IDENTITY, Nume NVARCHAR(100), Email NVARCHAR(100));
INSERT INTO dbo.Clienti (Nume, Email) VALUES (N'Ana', NULL), (N'Ion', N'ion@exemplu.ro');
GO

-- ---- Codul din carte ----
-- Tabel de istoric pentru audit
CREATE TABLE dbo.AuditClienti
(
    AuditId         INT PRIMARY KEY IDENTITY,
    Operatie        CHAR(1),               -- I = Insert, U = Update, D = Delete
    ClientId        INT,
    NumeVechi       NVARCHAR(100),
    NumeNou         NVARCHAR(100),
    EmailVechi      NVARCHAR(100),
    EmailNou        NVARCHAR(100),
    ModificatDe     NVARCHAR(128) DEFAULT SUSER_SNAME(),
    ModificatLa     DATETIME2 DEFAULT SYSDATETIME(),
    AplicatieSursa  NVARCHAR(128) DEFAULT APP_NAME()
);
GO

-- Trigger de audit pentru UPDATE
CREATE TRIGGER dbo.trg_AuditClienti_Update
ON dbo.Clienti
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO dbo.AuditClienti
        (Operatie, ClientId, NumeVechi, NumeNou, EmailVechi, EmailNou)
    SELECT
        'U',
        i.ClientId,
        d.Nume, i.Nume,        -- d = deleted (valori vechi)
        d.Email, i.Email       -- i = inserted (valori noi)
    FROM inserted i
    INNER JOIN deleted d ON i.ClientId = d.ClientId
    -- EXCEPT tratează NULL corect: o schimbare din NULL în valoare
    -- (sau invers) este detectată, spre deosebire de i.Email <> d.Email
    WHERE EXISTS (SELECT i.Nume, i.Email
                  EXCEPT
                  SELECT d.Nume, d.Email);
END;
GO
GO

-- ---- Verificare (nu apare în carte) ----
UPDATE dbo.Clienti SET Email = N'ana@exemplu.ro' WHERE ClientId = 1;  -- NULL -> valoare
UPDATE dbo.Clienti SET Email = NULL WHERE ClientId = 2;               -- valoare -> NULL
UPDATE dbo.Clienti SET Nume = Nume;                                   -- fără schimbare
SELECT Operatie, ClientId, EmailVechi, EmailNou FROM dbo.AuditClienti;  -- 2 rânduri
