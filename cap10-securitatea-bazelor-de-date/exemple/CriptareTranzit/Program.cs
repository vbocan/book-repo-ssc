using Microsoft.Data.SqlClient;

// Criptare strictă (TDS 8.0) și validarea certificatului serverului
var builder = new SqlConnectionStringBuilder
{
    DataSource = "dbserver.exemplu.ro",
    InitialCatalog = "ProductionDB",
    IntegratedSecurity = true,
    Encrypt = SqlConnectionEncryptOption.Strict,
    // HostNameInCertificate = "dbserver.exemplu.ro" // doar dacă numele diferă
};
string connectionString = builder.ConnectionString;
Console.WriteLine(connectionString);
