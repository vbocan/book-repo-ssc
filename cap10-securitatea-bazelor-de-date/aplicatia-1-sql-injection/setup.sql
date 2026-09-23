-- Rulați ca sa (membru sysadmin). Se poate rula de mai multe ori.
USE master;
GO
IF DB_ID(N'SQLInjectionLab') IS NOT NULL
BEGIN
    ALTER DATABASE SQLInjectionLab SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE SQLInjectionLab;
END;
GO
CREATE DATABASE SQLInjectionLab;
GO
USE SQLInjectionLab;
GO
-- Aplicația moștenită stochează parolele ÎN CLAR (coloana Parola). Este un
-- anti-pattern (capitolul 5); îl păstrăm ca să vedeți exact ce expune un
-- SQL injection. La pasul de remediere migrăm la parole cu hash (PBKDF2).
CREATE TABLE dbo.Utilizatori
(
    UtilizatorId  INT PRIMARY KEY IDENTITY,
    Username      NVARCHAR(50) NOT NULL UNIQUE,
    Parola        NVARCHAR(128) NULL,
    ParolaHash    VARBINARY(32) NULL,
    Salt          VARBINARY(16) NULL,
    Email         NVARCHAR(100),
    Rol           NVARCHAR(20) DEFAULT N'utilizator'
);

CREATE TABLE dbo.Produse
(
    ProdusId    INT PRIMARY KEY IDENTITY,
    Denumire    NVARCHAR(200) NOT NULL,
    Descriere   NVARCHAR(500),
    Pret        DECIMAL(10, 2),
    Stoc        INT
);

INSERT INTO dbo.Utilizatori (Username, Parola, Email, Rol)
VALUES
    (N'admin', N'SuperSecretAdmin!', N'admin@company.ro', N'administrator'),
    (N'ionescu', N'Parola123', N'ionescu@company.ro', N'utilizator'),
    (N'popescu', N'Test456!', N'popescu@company.ro', N'utilizator'),
    (N'vasilescu', N'Secure789', N'vasilescu@company.ro', N'manager');

INSERT INTO dbo.Produse (Denumire, Descriere, Pret, Stoc)
VALUES
    (N'Laptop Dell XPS 15', N'Laptop ultraperformant', 7500.00, 15),
    (N'Monitor LG 27"', N'Monitor 4K IPS', 2200.00, 30),
    (N'Tastatură mecanică', N'Switch-uri Cherry MX', 450.00, 50),
    (N'Mouse wireless', N'Senzor 25000 DPI', 350.00, 80);
GO
