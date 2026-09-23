using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

// Serverul de laborator (container mssql/server:2025), la 127.0.0.1, nu localhost
// (Pasul 0). TrustServerCertificate=true DOAR pentru certificatul autosemnat.
const string ConnectionString =
    "Server=127.0.0.1,1433;Database=SQLInjectionLab;" +
    "User Id=sa;Password=Parola_Lab_2026!;" +
    "Encrypt=Mandatory;TrustServerCertificate=true;";

const int Iteratii = 600_000; // PBKDF2-HMAC-SHA256, recomandarea OWASP

// ============================================================
// PARTEA 1: Funcții VULNERABILE (concatenare de string-uri)
// ============================================================

bool LoginVulnerabil(string username, string parola)
{
    using var conn = new SqlConnection(ConnectionString);
    conn.Open();

    // VULNERABIL: input-ul este lipit direct în textul comenzii
    string sql = $"SELECT Username, Rol FROM Utilizatori " +
                 $"WHERE Username = '{username}' AND Parola = '{parola}'";
    Console.WriteLine($"  SQL generat: {sql}");

    using var cmd = new SqlCommand(sql, conn);
    using var reader = cmd.ExecuteReader();
    if (reader.Read())
    {
        Console.WriteLine($"  Autentificat ca: {reader["Username"]} (rol: {reader["Rol"]})");
        return true;
    }
    return false;
}

void CautaProduseVulnerabil(string termen)
{
    using var conn = new SqlConnection(ConnectionString);
    conn.Open();

    // VULNERABIL: input-ul este lipit direct în textul comenzii
    string sql = $"SELECT Denumire, Descriere, Pret, Stoc FROM Produse " +
                 $"WHERE Denumire LIKE '%{termen}%'";
    Console.WriteLine($"  SQL generat: {sql}");

    using var cmd = new SqlCommand(sql, conn);
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
    {
        // Coloana Descriere (a 2-a) poate conține date exfiltrate prin UNION
        Console.WriteLine($"  {reader["Denumire"] ?? "(NULL)"} | {reader["Descriere"] ?? "(NULL)"}");
    }
}

// ============================================================
// PARTEA 2: Remedierea: migrarea la parole cu hash
// ============================================================

void MigreazaLaHash()
{
    using var conn = new SqlConnection(ConnectionString);
    conn.Open();

    // Citim utilizatorii cu parolă în clar
    var deMigrat = new List<(int Id, string Parola)>();
    using (var cmd = new SqlCommand(
        "SELECT UtilizatorId, Parola FROM Utilizatori WHERE Parola IS NOT NULL", conn))
    using (var reader = cmd.ExecuteReader())
        while (reader.Read())
            deMigrat.Add((reader.GetInt32(0), reader.GetString(1)));

    // Calculăm hash + salt și golim coloana Parola
    foreach (var (id, parola) in deMigrat)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(parola), salt,
            Iteratii, HashAlgorithmName.SHA256, outputLength: 32);

        using var upd = new SqlCommand(
            "UPDATE Utilizatori SET ParolaHash = @h, Salt = @s, Parola = NULL " +
            "WHERE UtilizatorId = @id", conn);
        upd.Parameters.Add("@h", SqlDbType.VarBinary, 32).Value = hash;
        upd.Parameters.Add("@s", SqlDbType.VarBinary, 16).Value = salt;
        upd.Parameters.Add("@id", SqlDbType.Int).Value = id;
        upd.ExecuteNonQuery();
    }
    Console.WriteLine($"  {deMigrat.Count} parole migrate la PBKDF2; coloana Parola golită.");
}

// ============================================================
// PARTEA 3: Funcții SECURIZATE (parametrizare + hash)
// ============================================================

bool LoginSecurizat(string username, string parola)
{
    using var conn = new SqlConnection(ConnectionString);
    conn.Open();

    // Numele de utilizator este transmis ca parametru
    const string sql =
        "SELECT ParolaHash, Salt, Rol FROM Utilizatori WHERE Username = @Username";
    using var cmd = new SqlCommand(sql, conn);
    cmd.Parameters.Add("@Username", SqlDbType.NVarChar, 50).Value = username;

    using var reader = cmd.ExecuteReader();
    if (!reader.Read())
        return false;

    var hashStocat = (byte[])reader["ParolaHash"];
    var salt = (byte[])reader["Salt"];
    string rol = (string)reader["Rol"];

    byte[] hashIntrodus = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(parola), salt,
        Iteratii, HashAlgorithmName.SHA256, outputLength: 32);

    if (CryptographicOperations.FixedTimeEquals(hashIntrodus, hashStocat))
    {
        Console.WriteLine($"  Autentificat ca: {username} (rol: {rol})");
        return true;
    }
    return false;
}

void CautaProduseSecurizat(string termen)
{
    using var conn = new SqlConnection(ConnectionString);
    conn.Open();

    const string sql =
        "SELECT Denumire, Descriere, Pret, Stoc FROM Produse WHERE Denumire LIKE @Termen";
    using var cmd = new SqlCommand(sql, conn);
    cmd.Parameters.Add("@Termen", SqlDbType.NVarChar, 202).Value = $"%{termen}%";

    using var reader = cmd.ExecuteReader();
    int n = 0;
    while (reader.Read()) { n++; }
    Console.WriteLine($"  {n} produse găsite (input tratat ca dată)");
}

// ============================================================
// DEMONSTRAȚII
// ============================================================
Console.WriteLine("=== SQL Injection Lab ===\n");

Console.WriteLine("--- Atac 1: bypass autentificare (aplicația vulnerabilă) ---");
Console.WriteLine("Input: username = admin' --, parola = orice\n");
bool r = LoginVulnerabil("admin' --", "orice");
Console.WriteLine($"  Rezultat: {(r ? "ACCES PERMIS" : "acces refuzat")}\n");

Console.WriteLine("--- Atac 2: exfiltrare prin UNION (căutare de produse vulnerabilă) ---");
string unionPayload = "' UNION SELECT NULL, Username + ':' + Parola, NULL, NULL FROM Utilizatori --";
Console.WriteLine($"Input: {unionPayload}\n");
CautaProduseVulnerabil(unionPayload);

Console.WriteLine("\n=== Remediere ===");
Console.WriteLine("Pas A: migrarea parolelor la hash");
MigreazaLaHash();

Console.WriteLine("\nPas B: aceleași atacuri contra codului securizat");
Console.WriteLine("[Login securizat] username = admin' --, parola = orice");
bool r2 = LoginSecurizat("admin' --", "orice");
Console.WriteLine($"  Rezultat: {(r2 ? "ACCES PERMIS" : "acces refuzat")}");
Console.WriteLine("[Login securizat] username = admin, parola corectă");
bool r3 = LoginSecurizat("admin", "SuperSecretAdmin!");
Console.WriteLine($"  Rezultat: {(r3 ? "ACCES PERMIS" : "acces refuzat")}");
Console.WriteLine("[Căutare securizată] cu payload UNION:");
CautaProduseSecurizat(unionPayload);
