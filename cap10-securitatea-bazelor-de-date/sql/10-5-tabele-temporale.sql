-- Tabele temporale și ștergerea din istoric
-- Carte: secțiunea 10.5, Tabele temporale (temporal tables) (10-securitatea-bazelor-de-date.md:723–735, 10-securitatea-bazelor-de-date.md:741–749, 10-securitatea-bazelor-de-date.md:755–760).
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
CREATE TABLE dbo.Produse
(
    ProdusId     INT PRIMARY KEY IDENTITY,
    Denumire     NVARCHAR(200) NOT NULL,
    Pret         DECIMAL(10, 2) NOT NULL,
    Categorie    NVARCHAR(50),
    -- Coloanele obligatorii pentru tabelele temporale
    ValidDin     DATETIME2 GENERATED ALWAYS AS ROW START,
    ValidPana    DATETIME2 GENERATED ALWAYS AS ROW END,
    PERIOD FOR SYSTEM_TIME (ValidDin, ValidPana)
)
WITH (SYSTEM_VERSIONING = ON
    (HISTORY_TABLE = dbo.ProduseIstoric));
GO

-- Ce produse existau pe 15 ianuarie 2026, la prânz (ora UTC)?
SELECT * FROM dbo.Produse
FOR SYSTEM_TIME AS OF '2026-01-15 12:00:00';

-- Istoricul complet al unui produs
SELECT * FROM dbo.Produse
FOR SYSTEM_TIME ALL
WHERE ProdusId = 42
ORDER BY ValidDin;
GO

ALTER TABLE dbo.Produse SET (SYSTEM_VERSIONING = OFF);
GO
DELETE FROM dbo.ProduseIstoric WHERE ProdusId = 42;
GO
ALTER TABLE dbo.Produse
    SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.ProduseIstoric));
