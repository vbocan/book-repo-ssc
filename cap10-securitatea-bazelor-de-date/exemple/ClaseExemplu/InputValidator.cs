using System.Text.RegularExpressions;

public class InputValidator
{
    // Validare prin whitelist — permite doar caractere așteptate
    public static bool EsteUsernameValid(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        if (username.Length is < 3 or > 50)
            return false;

        // Permite doar litere, cifre, puncte și underscore
        return Regex.IsMatch(username, @"^[a-zA-Z0-9._]+$");
    }

    // Validare ID numeric
    public static bool EsteIdValid(string id)
    {
        return int.TryParse(id, out int result) && result > 0;
    }

    // Validarea unei adrese de e-mail
    public static bool EsteEmailValid(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }

    // Validare pentru câmpuri de căutare — whitelist de caractere sigure
    public static string SanitizeazaTermenCautare(string termen)
    {
        if (string.IsNullOrWhiteSpace(termen))
            return string.Empty;

        // Elimină caracterele care nu sunt litere, cifre sau spații
        string sanitizat = Regex.Replace(termen, @"[^\w\s\-]", "");

        // Limitează lungimea
        return sanitizat.Length > 200
            ? sanitizat[..200]
            : sanitizat;
    }
}
