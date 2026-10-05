using System.Data;
using System.Globalization;
using Microsoft.Data.SqlClient;

void TesteazaAcces(string numeUtilizator, string parola, string descriere)
{
    // Conexiune ca utilizator departamental. Server local, certificat autosemnat.
    var b = new SqlConnectionStringBuilder
    {
        DataSource = "127.0.0.1,1433",
        InitialCatalog = "SQLInjectionLab",
        UserID = numeUtilizator,
        Password = parola,
        Encrypt = SqlConnectionEncryptOption.Mandatory,
        TrustServerCertificate = true
    };

    Console.WriteLine($"\n--- Conectat ca: {descriere} ---");
    using var conn = new SqlConnection(b.ConnectionString);
    conn.Open();

    const string selectSql =
        "SELECT ComandaId, Descriere, Valoare, Departament FROM ComenziDepartamentale";
    using (var cmd = new SqlCommand(selectSql, conn))
    using (var reader = cmd.ExecuteReader())
    {
        int count = 0;
        while (reader.Read())
        {
            // Cultură invariantă: format stabil, indiferent de setările sistemului
            string valoare = ((decimal)reader["Valoare"])
                .ToString("N2", CultureInfo.InvariantCulture);
            Console.WriteLine(
                $"  [{reader["ComandaId"]}] {reader["Descriere"],-24} " +
                $"{valoare,12} RON  ({reader["Departament"]})");
            count++;
        }
        Console.WriteLine($"  Total: {count} comenzi vizibile");
    }

    if (numeUtilizator == "UserIT")
    {
        try
        {
            const string insertSql =
                "INSERT INTO ComenziDepartamentale (Descriere, Valoare, Departament) " +
                "VALUES (@Desc, @Val, @Dept)";
            using var insertCmd = new SqlCommand(insertSql, conn);
            // Tipuri explicite, identice cu cele din schemă (NVARCHAR(200), DECIMAL(12,2), NVARCHAR(50))
            insertCmd.Parameters.Add("@Desc", SqlDbType.NVarChar, 200).Value = "Test HR";
            var pVal = insertCmd.Parameters.Add("@Val", SqlDbType.Decimal);
            pVal.Precision = 12;
            pVal.Scale = 2;
            pVal.Value = 1000.00m;
            insertCmd.Parameters.Add("@Dept", SqlDbType.NVarChar, 50).Value = "HR";
            insertCmd.ExecuteNonQuery();
            Console.WriteLine("  INSERT în departamentul HR: PERMIS (!)");
        }
        catch (SqlException)
        {
            Console.WriteLine("  INSERT în departamentul HR: BLOCAT de block predicate (RLS)");
        }
    }
}

Console.WriteLine("=== Test Row-Level Security ===");
TesteazaAcces("UserIT", "P@rola_IT!", "Departament IT");
TesteazaAcces("UserHR", "P@rola_HR!", "Departament HR");
TesteazaAcces("UserAdmin", "P@rola_Admin!", "Administrator");
