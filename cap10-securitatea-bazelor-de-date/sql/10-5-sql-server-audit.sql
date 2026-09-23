-- SQL Server Audit pe trei niveluri
-- Carte: secțiunea 10.5, SQL Server Audit (10-securitatea-bazelor-de-date.md:622–664).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): directorul de audit, baza ProductionDB, tabelul Clienti și procedura auditată ----
-- Atenție: ON_FAILURE = SHUTDOWN oprește serverul dacă auditul nu poate scrie. Doar pe containerul de laborator.
USE master;
GO
IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N'AuditProductie')
BEGIN
    RAISERROR(N'AuditProductie există deja: rulați întâi secțiunea de curățare de la final.', 16, 1);
    SET NOEXEC ON;
END;
GO
EXEC master.dbo.xp_create_subdir N'/var/opt/mssql/audit';
IF DB_ID(N'ProductionDB') IS NULL CREATE DATABASE ProductionDB;
GO
USE ProductionDB;
GO
IF OBJECT_ID(N'dbo.Clienti') IS NULL
    CREATE TABLE dbo.Clienti (ClientId INT PRIMARY KEY IDENTITY, Nume NVARCHAR(100));
GO
CREATE OR ALTER PROCEDURE dbo.usp_ModificaSalariu @AngajatId INT, @Salariu DECIMAL(10, 2)
AS
BEGIN
    SET NOCOUNT ON;
END;
GO

-- ---- Codul din carte ----
USE master;
GO
-- Nivelul 1: obiectul de audit (destinația evenimentelor)
CREATE SERVER AUDIT AuditProductie
    TO FILE (
        FILEPATH = '/var/opt/mssql/audit/',   -- pe Windows, de exemplu 'D:\Audit\'
        MAXSIZE = 100 MB,
        MAX_ROLLOVER_FILES = 10
    )
    WITH (
        QUEUE_DELAY = 1000,          -- cel mult 1 secundă întârziere
        ON_FAILURE = SHUTDOWN        -- oprește serverul dacă auditul nu poate scrie
    );
GO
ALTER SERVER AUDIT AuditProductie WITH (STATE = ON);
GO

-- Nivelul 2: evenimente la nivel de server
CREATE SERVER AUDIT SPECIFICATION AuditLoginuri
    FOR SERVER AUDIT AuditProductie
    ADD (FAILED_LOGIN_GROUP),               -- autentificări eșuate
    ADD (SUCCESSFUL_LOGIN_GROUP),           -- autentificări reușite
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),  -- modificări ale rolurilor de server
    ADD (DATABASE_CHANGE_GROUP)             -- creare/ștergere/modificare baze de date
    WITH (STATE = ON);
GO

-- Nivelul 3: evenimente la nivel de bază de date
USE ProductionDB;
GO
CREATE DATABASE AUDIT SPECIFICATION AuditDateSensibile
    FOR SERVER AUDIT AuditProductie
    ADD (SELECT, INSERT, UPDATE, DELETE
        ON dbo.Clienti BY public),            -- orice acces la tabelul Clienti
    ADD (EXECUTE
        ON dbo.usp_ModificaSalariu BY public) -- execuția procedurii de salarii
    WITH (STATE = ON);
GO

-- Citirea evenimentelor înregistrate
SELECT event_time, action_id, server_principal_name, statement
FROM sys.fn_get_audit_file('/var/opt/mssql/audit/*.sqlaudit', DEFAULT, DEFAULT)
ORDER BY event_time DESC;
GO

-- ---- Curățare (nu apare în carte) ----
SET NOEXEC OFF;
GO
-- Curățare: auditul cu ON_FAILURE = SHUTDOWN nu rămâne activ pe serverul de laborator
USE ProductionDB;
ALTER DATABASE AUDIT SPECIFICATION AuditDateSensibile WITH (STATE = OFF);
DROP DATABASE AUDIT SPECIFICATION AuditDateSensibile;
GO
USE master;
ALTER SERVER AUDIT SPECIFICATION AuditLoginuri WITH (STATE = OFF);
DROP SERVER AUDIT SPECIFICATION AuditLoginuri;
ALTER SERVER AUDIT AuditProductie WITH (STATE = OFF);
DROP SERVER AUDIT AuditProductie;
