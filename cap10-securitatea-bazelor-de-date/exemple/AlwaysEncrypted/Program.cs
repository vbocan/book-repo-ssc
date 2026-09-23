using System.Data;
using Microsoft.Data.SqlClient;

// Tabelul (creat în prealabil cu SSMS sau cu PowerShell SqlServer):
//   CNP        CHAR(13)      COLLATE Latin1_General_BIN2  criptare deterministă
//   Diagnostic NVARCHAR(200)                              criptare randomizată
var builder = new SqlConnectionStringBuilder
{
    DataSource = "dbserver",
    InitialCatalog = "MedicalDB",
    IntegratedSecurity = true,
    Encrypt = SqlConnectionEncryptOption.Strict,
    ColumnEncryptionSetting = SqlConnectionColumnEncryptionSetting.Enabled
};

using var connection = new SqlConnection(builder.ConnectionString);
connection.Open();

// Inserare: driverul criptează automat valorile parametrilor
// pentru coloanele configurate cu Always Encrypted
const string insertSql = """
    INSERT INTO dbo.Pacienti (Nume, CNP, Diagnostic)
    VALUES (@Nume, @CNP, @Diagnostic)
    """;

using (var insertCmd = new SqlCommand(insertSql, connection))
{
    insertCmd.Parameters.Add("@Nume", SqlDbType.NVarChar, 100).Value = "Ionescu Maria";
    insertCmd.Parameters.Add("@CNP", SqlDbType.Char, 13).Value = "2850415123456";
    insertCmd.Parameters.Add("@Diagnostic", SqlDbType.NVarChar, 200).Value = "Hipertensiune";
    insertCmd.ExecuteNonQuery();
}

// Căutare după egalitate pe coloana cu criptare deterministă
const string selectSql = "SELECT Nume, CNP, Diagnostic FROM dbo.Pacienti WHERE CNP = @CNP";
using var selectCmd = new SqlCommand(selectSql, connection);
selectCmd.Parameters.Add("@CNP", SqlDbType.Char, 13).Value = "2850415123456";

using var reader = selectCmd.ExecuteReader();
while (reader.Read())
{
    // Valorile sunt deja decriptate de driver
    Console.WriteLine($"{reader["Nume"]} | CNP: {reader["CNP"]} | " +
                      $"Diagnostic: {reader["Diagnostic"]}");
}
