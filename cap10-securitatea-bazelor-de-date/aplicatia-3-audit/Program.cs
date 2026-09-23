using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

const string ConnStr =
    "Server=127.0.0.1,1433;Database=SQLInjectionLab;" +
    "User Id=sa;Password=Parola_Lab_2026!;" +
    "Encrypt=Mandatory;TrustServerCertificate=true;";

void Exec(SqlConnection conn, string sql)
{
    using var cmd = new SqlCommand(sql, conn);
    cmd.ExecuteNonQuery();
}

void ConfigureazaAudit()
{
    using var conn = new SqlConnection(ConnStr);
    conn.Open();

    Exec(conn, """
        DROP TABLE IF EXISTS dbo.JurnalAudit;
        IF OBJECT_ID('dbo.ProduseAuditate') IS NOT NULL
        BEGIN
            IF (SELECT temporal_type FROM sys.tables WHERE name = 'ProduseAuditate') = 2
                ALTER TABLE dbo.ProduseAuditate SET (SYSTEM_VERSIONING = OFF);
            DROP TABLE IF EXISTS dbo.ProduseAuditate;
            DROP TABLE IF EXISTS dbo.ProduseAuditateIstoric;
        END;
        """);

    Exec(conn, """
        CREATE TABLE dbo.ProduseAuditate
        (
            ProdusId    INT PRIMARY KEY IDENTITY,
            Denumire    NVARCHAR(200) NOT NULL,
            Pret        DECIMAL(10,2) NOT NULL,
            Stoc        INT NOT NULL,
            Categorie   NVARCHAR(50),
            ValidDin    DATETIME2 GENERATED ALWAYS AS ROW START,
            ValidPana   DATETIME2 GENERATED ALWAYS AS ROW END,
            PERIOD FOR SYSTEM_TIME (ValidDin, ValidPana)
        )
        WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.ProduseAuditateIstoric));
        """);

    Exec(conn, """
        CREATE TABLE dbo.JurnalAudit
        (
            EventId        INT PRIMARY KEY IDENTITY,
            TabelAfectat   NVARCHAR(128),
            Operatie       NVARCHAR(10),
            InregistrareId INT,
            ValoriVechi    NVARCHAR(MAX),
            ValoriNoi      NVARCHAR(MAX),
            Utilizator     NVARCHAR(128) DEFAULT SUSER_SNAME(),
            DataOra        DATETIME2 DEFAULT SYSDATETIME(),
            Aplicatie      NVARCHAR(128) DEFAULT APP_NAME()
        );
        """);

    // Fiecare CREATE TRIGGER trebuie să fie prima instrucțiune din batch
    Exec(conn, """
        CREATE OR ALTER TRIGGER dbo.trg_ProduseAudit_Insert
        ON dbo.ProduseAuditate AFTER INSERT
        AS
        BEGIN
            SET NOCOUNT ON;
            INSERT INTO dbo.JurnalAudit (TabelAfectat, Operatie, InregistrareId, ValoriNoi)
            SELECT N'ProduseAuditate', N'INSERT', i.ProdusId,
                   CONCAT(N'Pret=', i.Pret, N' | Stoc=', i.Stoc)
            FROM inserted i;
        END;
        """);
    Exec(conn, """
        CREATE OR ALTER TRIGGER dbo.trg_ProduseAudit_Update
        ON dbo.ProduseAuditate AFTER UPDATE
        AS
        BEGIN
            SET NOCOUNT ON;
            INSERT INTO dbo.JurnalAudit
                (TabelAfectat, Operatie, InregistrareId, ValoriVechi, ValoriNoi)
            SELECT N'ProduseAuditate', N'UPDATE', i.ProdusId,
                   CONCAT(N'Pret=', d.Pret, N' | Stoc=', d.Stoc),
                   CONCAT(N'Pret=', i.Pret, N' | Stoc=', i.Stoc)
            FROM inserted i INNER JOIN deleted d ON i.ProdusId = d.ProdusId;
        END;
        """);
    Console.WriteLine("Audit configurat cu succes.");
}

void SimuleazaActivitate()
{
    using var conn = new SqlConnection(ConnStr);
    conn.Open();
    Console.WriteLine("\n--- Simulare activitate ---");

    // Literalele cu diacritice folosesc prefixul N
    string[] produse =
    {
        "(N'Laptop Lenovo', 5200.00, 20, N'Electronice')",
        "(N'Imprimantă laser', 1800.00, 10, N'Echipamente')",
        "(N'Cabluri UTP Cat6', 15.00, 500, N'Rețelistică')",
        "(N'SSD 1TB NVMe', 450.00, 100, N'Componente')"
    };
    foreach (var p in produse)
        Exec(conn, "INSERT INTO dbo.ProduseAuditate (Denumire, Pret, Stoc, Categorie) VALUES " + p);
    Console.WriteLine("  4 produse inserate.");

    Exec(conn, "UPDATE dbo.ProduseAuditate SET Pret = 4800.00 WHERE Denumire = N'Laptop Lenovo'");
    Console.WriteLine("  Preț laptop: 5200 -> 4800.");
    Exec(conn, "UPDATE dbo.ProduseAuditate SET Pret = 50.00 WHERE Denumire = N'Laptop Lenovo'");
    Console.WriteLine("  Preț laptop: 4800 -> 50 (suspect).");
}

void AnalizeazaAudit()
{
    using var conn = new SqlConnection(ConnStr);
    conn.Open();

    Console.WriteLine("\n--- Activități suspecte detectate ---");
    const string sql = """
        SELECT ValoriVechi, ValoriNoi, Utilizator, DataOra
        FROM dbo.JurnalAudit
        WHERE Operatie = N'UPDATE' AND ValoriVechi IS NOT NULL AND ValoriNoi IS NOT NULL
        """;
    using var cmd = new SqlCommand(sql, conn);
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
    {
        string vechi = (string)reader["ValoriVechi"];
        string nou = (string)reader["ValoriNoi"];
        var mv = Regex.Match(vechi, @"Pret=(\d+\.?\d*)");
        var mn = Regex.Match(nou, @"Pret=(\d+\.?\d*)");
        if (mv.Success && mn.Success)
        {
            // Valorile din audit sunt scrise de SQL Server cu punct zecimal;
            // le parsăm cu InvariantCulture, ca să nu depindem de setările sistemului.
            decimal pretVechi = decimal.Parse(mv.Groups[1].Value, CultureInfo.InvariantCulture);
            decimal pretNou = decimal.Parse(mn.Groups[1].Value, CultureInfo.InvariantCulture);
            if (pretVechi > 0)
            {
                decimal procent = Math.Abs((pretNou - pretVechi) / pretVechi * 100);
                if (procent > 50)
                    Console.WriteLine(
                        $"  ALERTĂ: modificare de preț de {procent.ToString("F1", CultureInfo.InvariantCulture)}% " +
                        $"(de la {pretVechi.ToString(CultureInfo.InvariantCulture)} " +
                        $"la {pretNou.ToString(CultureInfo.InvariantCulture)}) " +
                        $"de către {reader["Utilizator"]}");
            }
        }
    }
    reader.Close();

    Console.WriteLine("\n--- Istoricul prețului pentru 'Laptop Lenovo' (tabel temporal) ---");
    const string sqlT = """
        SELECT Pret, ValidDin, ValidPana
        FROM dbo.ProduseAuditate FOR SYSTEM_TIME ALL
        WHERE Denumire = N'Laptop Lenovo'
        ORDER BY ValidDin
        """;
    using var cmdT = new SqlCommand(sqlT, conn);
    using var rt = cmdT.ExecuteReader();
    while (rt.Read())
        Console.WriteLine(
            $"    {((DateTime)rt["ValidDin"]):yyyy-MM-dd HH:mm:ss} .. " +
            $"{((DateTime)rt["ValidPana"]):yyyy-MM-dd HH:mm:ss}: " +
            $"Preț = {((decimal)rt["Pret"]).ToString("N2", CultureInfo.InvariantCulture)} RON");
}

ConfigureazaAudit();
SimuleazaActivitate();
AnalizeazaAudit();
