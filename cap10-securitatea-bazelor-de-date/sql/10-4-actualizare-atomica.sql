-- Actualizarea atomică a soldului (concurență)
-- Carte: secțiunea 10.4, Concurență optimistă și pesimistă (10-securitatea-bazelor-de-date.md:597–600).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): tabelul și parametrii (@Suma mai mare decât soldul) ----
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
CREATE TABLE dbo.ConturiBancare (ContId INT PRIMARY KEY, Sold DECIMAL(12, 2) NOT NULL);
INSERT INTO dbo.ConturiBancare VALUES (1, 100.00);
GO
DECLARE @ContId INT = 1, @Suma DECIMAL(12, 2) = 150.00;

-- ---- Codul din carte ----
UPDATE dbo.ConturiBancare
SET Sold = Sold - @Suma
WHERE ContId = @ContId AND Sold >= @Suma;
-- 0 rânduri afectate = fonduri insuficiente (sau cont inexistent)

-- ---- Verificare, în același lot (nu apare în carte) ----
SELECT @@ROWCOUNT AS RanduriAfectate;   -- 0: fonduri insuficiente
