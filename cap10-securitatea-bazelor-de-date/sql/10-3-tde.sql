-- Transparent Data Encryption (TDE)
-- Carte: capitolul 10, secțiunea 10.3, Transparent Data Encryption.
-- Rulați pe serverul de laborator din compose.yaml (vezi README.md). Scriptul se poate rula de mai multe ori.

-- ---- Pregătire (nu apare în carte): baza de date ProductionDB; oprire dacă scriptul a mai rulat ----
-- Scriptul creează chei și certificate în baza master: rulați-l O SINGURĂ DATĂ, pe containerul de laborator.
USE master;
GO
IF EXISTS (SELECT 1 FROM sys.certificates WHERE name = N'CertificatTDE')
BEGIN
    RAISERROR(N'CertificatTDE există deja: scriptul a mai rulat. Recreați containerul (docker compose down -v).', 16, 1);
    SET NOEXEC ON;
END;
GO
IF DB_ID(N'ProductionDB') IS NULL CREATE DATABASE ProductionDB;
GO

-- ---- Codul din carte ----
-- Pas 1: Database Master Key în baza master (protejată de o parolă și,
-- automat, de Service Master Key a instanței)
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = N'P@rolaF0artePutern1ca!';
GO

-- Pas 2: certificatul care va proteja cheia de criptare a bazei de date
CREATE CERTIFICATE CertificatTDE
    WITH SUBJECT = N'Certificat TDE pentru baza de date ProductionDB';
GO

-- Pas 3: backup-ul certificatului și al cheii private, IMEDIAT după creare.
-- Fără el, backup-urile criptate nu pot fi restaurate pe alt server.
BACKUP CERTIFICATE CertificatTDE
    TO FILE = '/var/opt/mssql/backup/CertificatTDE.cer'
    WITH PRIVATE KEY (
        FILE = '/var/opt/mssql/backup/CertificatTDE.pvk',
        ENCRYPTION BY PASSWORD = N'P@rola_Backup_Cert!'
    );
GO

-- Pas 4: cheia de criptare a bazei de date (DEK), protejată de certificat
USE ProductionDB;
CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE CertificatTDE;
GO

-- Pas 5: activarea criptării (rulează în fundal)
ALTER DATABASE ProductionDB SET ENCRYPTION ON;
GO

-- Verificare
SELECT DB_NAME(database_id) AS BazaDeDate, encryption_state_desc, key_algorithm, key_length
FROM sys.dm_database_encryption_keys;
GO

-- ---- Final (nu apare în carte) ----
SET NOEXEC OFF;
