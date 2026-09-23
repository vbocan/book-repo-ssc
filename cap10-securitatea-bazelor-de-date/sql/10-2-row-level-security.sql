-- Row-Level Security cu predicate de filtrare și de blocare
-- Carte: secțiunea 10.2, Row-Level Security (RLS) (10-securitatea-bazelor-de-date.md:170–212).
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

-- ---- Codul din carte ----
-- Tabel cu comenzi, fiecare asociată unui departament
CREATE TABLE dbo.Comenzi
(
    ComandaId    INT PRIMARY KEY IDENTITY,
    Produs       NVARCHAR(100),
    Cantitate    INT,
    Pret         DECIMAL(10, 2),
    Departament  NVARCHAR(50),
    DataComanda  DATETIME2 DEFAULT SYSDATETIME()
);

INSERT INTO dbo.Comenzi (Produs, Cantitate, Pret, Departament)
VALUES
    (N'Laptop Dell', 5, 4500.00, N'IT'),
    (N'Monitor 27"', 10, 1200.00, N'IT'),
    (N'Birou ergonomic', 3, 2800.00, N'HR'),
    (N'Scaun ergonomic', 15, 1500.00, N'HR'),
    (N'Licență Office', 50, 250.00, N'IT'),
    (N'Catering eveniment', 1, 5000.00, N'Marketing');
GO

-- Funcția de predicat: rândul este vizibil dacă departamentul său are
-- același nume ca utilizatorul curent sau dacă utilizatorul este db_owner
CREATE FUNCTION dbo.fn_FiltruDepartament(@Departament NVARCHAR(50))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS result
    WHERE @Departament = USER_NAME()
       OR IS_MEMBER('db_owner') = 1;
GO

-- Politica de securitate: filtrare la citire, blocare la INSERT și la UPDATE
CREATE SECURITY POLICY dbo.PoliticaDepartament
    ADD FILTER PREDICATE dbo.fn_FiltruDepartament(Departament)
        ON dbo.Comenzi,
    ADD BLOCK PREDICATE dbo.fn_FiltruDepartament(Departament)
        ON dbo.Comenzi AFTER INSERT,
    ADD BLOCK PREDICATE dbo.fn_FiltruDepartament(Departament)
        ON dbo.Comenzi AFTER UPDATE
WITH (STATE = ON);
GO
GO

-- ---- Verificare (nu apare în carte) ----
CREATE USER IT WITHOUT LOGIN;
GRANT SELECT, INSERT, UPDATE ON dbo.Comenzi TO IT;
GO
EXECUTE AS USER = 'IT';
SELECT ComandaId, Produs, Departament FROM dbo.Comenzi;   -- doar rândurile IT
BEGIN TRY
    UPDATE dbo.Comenzi SET Departament = N'HR' WHERE ComandaId = 1;
    PRINT N'UPDATE permis (neașteptat)';
END TRY
BEGIN CATCH
    PRINT N'UPDATE blocat de block predicate: ' + ERROR_MESSAGE();
END CATCH;
REVERT;
