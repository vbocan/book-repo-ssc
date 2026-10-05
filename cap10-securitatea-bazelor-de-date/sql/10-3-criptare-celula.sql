-- Criptarea la nivel de celulă
-- Carte: capitolul 10, secțiunea 10.3, Criptarea la nivel de celulă.
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date a aplicației ----
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
-- Ierarhia de chei în baza de date a aplicației
CREATE MASTER KEY ENCRYPTION BY PASSWORD = N'Alt@ParolaPentruDMK1';
CREATE CERTIFICATE CertificatAplicatie WITH SUBJECT = N'Criptare coloane';
CREATE SYMMETRIC KEY CheieDate
    WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE CertificatAplicatie;

CREATE TABLE dbo.Pacienti
(
    PacientId          INT IDENTITY PRIMARY KEY,
    Nume               NVARCHAR(100),
    DiagnosticCriptat  VARBINARY(512)
);
GO

-- Criptarea la inserare
OPEN SYMMETRIC KEY CheieDate
    DECRYPTION BY CERTIFICATE CertificatAplicatie;

INSERT INTO dbo.Pacienti (Nume, DiagnosticCriptat)
VALUES (N'Popescu Ion',
    EncryptByKey(Key_GUID('CheieDate'), N'Diagnostic sensibil'));

CLOSE SYMMETRIC KEY CheieDate;
GO

-- Decriptarea la citire
OPEN SYMMETRIC KEY CheieDate
    DECRYPTION BY CERTIFICATE CertificatAplicatie;

SELECT Nume,
    CONVERT(NVARCHAR(200), DecryptByKey(DiagnosticCriptat)) AS Diagnostic
FROM dbo.Pacienti;

CLOSE SYMMETRIC KEY CheieDate;
