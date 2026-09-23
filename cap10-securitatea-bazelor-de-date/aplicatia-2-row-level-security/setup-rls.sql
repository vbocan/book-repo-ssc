USE SQLInjectionLab;
GO
-- Logini SQL (necesită autentificare mixtă activată)
IF SUSER_ID(N'UserIT') IS NULL CREATE LOGIN UserIT WITH PASSWORD = N'P@rola_IT!';
IF SUSER_ID(N'UserHR') IS NULL CREATE LOGIN UserHR WITH PASSWORD = N'P@rola_HR!';
IF SUSER_ID(N'UserAdmin') IS NULL CREATE LOGIN UserAdmin WITH PASSWORD = N'P@rola_Admin!';
GO
IF USER_ID(N'UserIT') IS NULL CREATE USER UserIT FOR LOGIN UserIT;
IF USER_ID(N'UserHR') IS NULL CREATE USER UserHR FOR LOGIN UserHR;
IF USER_ID(N'UserAdmin') IS NULL CREATE USER UserAdmin FOR LOGIN UserAdmin;
GO
DROP TABLE IF EXISTS dbo.ComenziDepartamentale;
GO
CREATE TABLE dbo.ComenziDepartamentale
(
    ComandaId     INT PRIMARY KEY IDENTITY,
    Descriere     NVARCHAR(200),
    Valoare       DECIMAL(12, 2),
    Departament   NVARCHAR(50),
    DataComanda   DATETIME2 DEFAULT SYSDATETIME(),
    Status        NVARCHAR(20) DEFAULT N'Nouă'
);
INSERT INTO dbo.ComenziDepartamentale (Descriere, Valoare, Departament)
VALUES
    (N'Licențe Visual Studio', 15000.00, N'IT'),
    (N'Servere rack', 45000.00, N'IT'),
    (N'Training management', 8000.00, N'HR'),
    (N'Echipamente birou', 12000.00, N'HR'),
    (N'Switch-uri rețea', 22000.00, N'IT'),
    (N'Cursuri limba engleză', 5000.00, N'HR');
GO
GRANT SELECT, INSERT, UPDATE ON dbo.ComenziDepartamentale TO UserIT, UserHR;
GRANT SELECT ON dbo.ComenziDepartamentale TO UserAdmin;
GO
CREATE OR ALTER FUNCTION dbo.fn_FiltrareComandaDepartament(@Departament NVARCHAR(50))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS result
    WHERE @Departament = CASE USER_NAME()
                            WHEN 'UserIT' THEN 'IT'
                            WHEN 'UserHR' THEN 'HR'
                            ELSE NULL
                         END
       OR USER_NAME() = 'UserAdmin'
       OR IS_MEMBER('db_owner') = 1;
GO
DROP SECURITY POLICY IF EXISTS dbo.PoliticaComenzi;
GO
CREATE SECURITY POLICY dbo.PoliticaComenzi
    ADD FILTER PREDICATE
        dbo.fn_FiltrareComandaDepartament(Departament) ON dbo.ComenziDepartamentale,
    ADD BLOCK PREDICATE
        dbo.fn_FiltrareComandaDepartament(Departament) ON dbo.ComenziDepartamentale AFTER INSERT,
    ADD BLOCK PREDICATE
        dbo.fn_FiltrareComandaDepartament(Departament) ON dbo.ComenziDepartamentale AFTER UPDATE
WITH (STATE = ON);
GO
