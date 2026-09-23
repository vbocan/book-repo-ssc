-- Proceduri stocate: securizat, vulnerabil și SQL dinamic cu listă albă
-- Carte: secțiunea 10.6, Prevenirea SQL injection, 2. Proceduri stocate (10-securitatea-bazelor-de-date.md:1028–1050, 10-securitatea-bazelor-de-date.md:1058–1081).
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): tabelul Produse (usp_CautaProduseVulnerabil este INTENȚIONAT vulnerabilă) ----
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
CREATE TABLE dbo.Produse (ProdusId INT PRIMARY KEY IDENTITY, Denumire NVARCHAR(200), Pret DECIMAL(10, 2));
INSERT INTO dbo.Produse (Denumire, Pret) VALUES (N'Laptop', 5000), (N'Mouse', 90);
GO

-- ---- Codul din carte ----
-- Procedură stocată securizată: parametrul este folosit direct în interogare
CREATE PROCEDURE dbo.usp_CautaProduse
    @TermenCautare NVARCHAR(100)
AS
BEGIN
    SELECT ProdusId, Denumire, Pret
    FROM dbo.Produse
    WHERE Denumire LIKE N'%' + @TermenCautare + N'%';
END;
GO

-- Procedură stocată VULNERABILĂ: SQL dinamic construit prin concatenare
CREATE PROCEDURE dbo.usp_CautaProduseVulnerabil
    @TermenCautare NVARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(500);
    SET @sql = N'SELECT ProdusId, Denumire, Pret ' +
               N'FROM dbo.Produse ' +
               N'WHERE Denumire LIKE N''%' + @TermenCautare + N'%''';
    EXEC (@sql);  -- vulnerabil la SQL injection!
END;
GO

-- SQL dinamic securizat cu sp_executesql
CREATE PROCEDURE dbo.usp_CautaDinamic
    @TabelNume NVARCHAR(128),
    @TermenCautare NVARCHAR(100)
AS
BEGIN
    -- Numele tabelului este un identificator și nu poate fi parametrizat,
    -- deci se validează printr-o listă albă
    IF @TabelNume NOT IN (N'Produse', N'Categorii', N'Producatori')
    BEGIN
        RAISERROR(N'Tabel invalid.', 16, 1);
        RETURN;
    END;

    DECLARE @sql NVARCHAR(500) =
        N'SELECT * FROM dbo.' + QUOTENAME(@TabelNume) +
        N' WHERE Denumire LIKE @termen';
    DECLARE @tipar NVARCHAR(102) = N'%' + @TermenCautare + N'%';

    EXEC sp_executesql @sql,
        N'@termen NVARCHAR(102)',
        @termen = @tipar;
END;
GO
GO

-- ---- Verificare (nu apare în carte) ----
EXEC dbo.usp_CautaProduse N'Lap';                  -- Laptop
EXEC dbo.usp_CautaProduse N''' OR 1=1 --';         -- niciun rând: input tratat ca text
EXEC dbo.usp_CautaProduseVulnerabil N''' OR 1=1 --'; -- TOATE rândurile: injecție reușită
EXEC dbo.usp_CautaDinamic N'Produse', N'ous';       -- Mouse
BEGIN TRY
    EXEC dbo.usp_CautaDinamic N'Produse; DROP TABLE x', N'a';
END TRY
BEGIN CATCH
    PRINT ERROR_MESSAGE();                            -- Tabel invalid.
END CATCH;
