-- Ledger tables (append-only și updatable)
-- Carte: secțiunea 10.5, Ledger tables (10-securitatea-bazelor-de-date.md:772–803).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date ----
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
-- Verificarea digestului cere ALLOW_SNAPSHOT_ISOLATION ON
ALTER DATABASE SSCCap10 SET ALLOW_SNAPSHOT_ISOLATION ON;
GO

-- ---- Codul din carte ----
-- Append-only: se permit doar inserări (jurnale, tranzacții financiare)
CREATE TABLE dbo.JurnalTranzactii
(
    TranzactieId  INT IDENTITY PRIMARY KEY,
    ContId        INT NOT NULL,
    Suma          DECIMAL(12, 2) NOT NULL,
    Operator      NVARCHAR(128) NOT NULL DEFAULT SUSER_SNAME()
)
WITH (LEDGER = ON (APPEND_ONLY = ON));
GO

-- Updatable: se permit modificări, dar fiecare versiune rămâne în istoric
CREATE TABLE dbo.Salarii
(
    AngajatId  INT PRIMARY KEY,
    Salariu    DECIMAL(10, 2) NOT NULL
)
WITH (SYSTEM_VERSIONING = ON, LEDGER = ON);
GO

INSERT INTO dbo.JurnalTranzactii (ContId, Suma) VALUES (1001, 250.00);
UPDATE dbo.JurnalTranzactii SET Suma = 25.00 WHERE TranzactieId = 1;
-- Msg 37359: Updates are not allowed for the append only Ledger table 'dbo.JurnalTranzactii'.

INSERT INTO dbo.Salarii VALUES (7, 8000);
UPDATE dbo.Salarii SET Salariu = 9500 WHERE AngajatId = 7;
SELECT AngajatId, Salariu, ledger_operation_type_desc
FROM dbo.Salarii_Ledger;   -- view generat automat: INSERT 8000, INSERT 9500, DELETE 8000

-- Generarea digestului și verificarea integrității
-- (verificarea cere ALLOW_SNAPSHOT_ISOLATION ON pe baza de date)
EXEC sys.sp_generate_database_ledger_digest;   -- digestul care se exportă
GO

-- ---- Verificare (nu apare în carte) ----
CREATE TABLE #digest (d NVARCHAR(MAX));
INSERT INTO #digest EXEC sys.sp_generate_database_ledger_digest;
DECLARE @digest NVARCHAR(MAX) = (SELECT d FROM #digest);
EXEC sys.sp_verify_database_ledger @digest;
PRINT N'Ledger verificat.';
