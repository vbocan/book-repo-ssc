using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

public static class Autentificare
{
    private const int Iteratii = 600_000;   // PBKDF2-HMAC-SHA256, recomandarea OWASP

    // Cod SECURIZAT: interogare parametrizată + verificarea unui hash de parolă
    public static bool Autentifica(string username, string parola)
    {
        const string connectionString =
            "Server=localhost;Database=AppDB;Integrated Security=true;" +
            "Encrypt=Mandatory;";

        // Numele de utilizator este transmis ca parametru, nu concatenat în text
        const string query =
            "SELECT ParolaHash, Salt FROM Utilizatori WHERE Username = @Username";

        using var connection = new SqlConnection(connectionString);
        connection.Open();
        using var command = new SqlCommand(query, connection);
        command.Parameters.Add("@Username", SqlDbType.NVarChar, 50).Value = username;

        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return false;   // utilizator inexistent

        var hashStocat = (byte[])reader["ParolaHash"];
        var salt = (byte[])reader["Salt"];

        // Recalculăm hash-ul parolei introduse cu ACELAȘI salt și îl comparăm
        // în timp constant. Parola nu este niciodată stocată sau comparată în clar.
        byte[] hashIntrodus = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(parola), salt,
            Iteratii, HashAlgorithmName.SHA256, outputLength: 32);

        return CryptographicOperations.FixedTimeEquals(hashIntrodus, hashStocat);
    }
}
