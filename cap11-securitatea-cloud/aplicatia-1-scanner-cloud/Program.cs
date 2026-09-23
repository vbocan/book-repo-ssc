// ============================================================
// Program principal: testare cu date simulate
// (instrucțiunile top-level stau la începutul fișierului;
//  tipurile sunt declarate după ele)
// ============================================================

var configuratie = new ConfiguratieCloud
{
    Buckets =
    [
        new StorageBucket
        {
            Nume = "date-clienti-prod",
            AccesPublic = true,     // Misconfigurare critică!
            CriptareActivata = false,
            LoggingAccesActivat = false,
            VersionareActivata = false
        },
        new StorageBucket
        {
            Nume = "backup-zilnic",
            AccesPublic = false,
            CriptareActivata = true,
            LoggingAccesActivat = true,
            VersionareActivata = true
        }
    ],
    SecurityGroups =
    [
        new SecurityGroup
        {
            Nume = "sg-web-servers",
            Descriere = "Security group pentru serverele web",
            ReguliIngress =
            [
                new SecurityGroupRule
                {
                    Protocol = "tcp", PortStart = 443,
                    PortEnd = 443, Sursa = "0.0.0.0/0"
                },
                new SecurityGroupRule
                {
                    Protocol = "tcp", PortStart = 22,
                    PortEnd = 22, Sursa = "0.0.0.0/0"
                    // SSH deschis la internet: risc!
                }
            ]
        },
        new SecurityGroup
        {
            Nume = "sg-baza-de-date",
            Descriere = "Security group pentru baza de date",
            ReguliIngress =
            [
                new SecurityGroupRule
                {
                    Protocol = "tcp", PortStart = 5432,
                    PortEnd = 5432, Sursa = "0.0.0.0/0"
                    // PostgreSQL deschis la internet: critic!
                }
            ]
        },
        new SecurityGroup
        {
            Nume = "sg-dezvoltare",
            Descriere = "Security group pentru dezvoltare",
            ReguliIngress =
            [
                new SecurityGroupRule
                {
                    Protocol = "tcp", PortStart = 1,
                    PortEnd = 65535, Sursa = "0.0.0.0/0"
                    // Toate porturile deschise: extrem de periculos!
                }
            ]
        }
    ],
    ConturiIAM =
    [
        new ContIAM
        {
            NumeUtilizator = "admin-principal",
            AccesConsola = true,
            MFAActivat = false,
            AreAccessKey = true,
            VarstaAccessKeyZile = 180,
            Politici = ["arn:aws:iam::aws:policy/AdministratorAccess"],
            UltimaAutentificare = DateTime.UtcNow.AddDays(-5)
        },
        new ContIAM
        {
            NumeUtilizator = "service-account-api",
            EsteContDeServiciu = true,
            AreAccessKey = true,
            VarstaAccessKeyZile = 45,
            Politici =
            [
                "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
            ],
            UltimaAutentificare = DateTime.UtcNow.AddDays(-1)
        },
        new ContIAM
        {
            NumeUtilizator = "fost-angajat",
            AccesConsola = true,
            MFAActivat = true,
            AreAccessKey = true,
            VarstaAccessKeyZile = 365,
            Politici = ["arn:aws:iam::aws:policy/PowerUserAccess"],
            UltimaAutentificare = DateTime.UtcNow.AddDays(-200)
        }
    ]
};

var scanner = new CloudSecurityScanner();
var constatari = scanner.Scaneaza(configuratie);

Console.WriteLine("═══════════════════════════════════════════════════");
Console.WriteLine("   RAPORT DE SECURITATE: CONFIGURAȚIE CLOUD");
Console.WriteLine("═══════════════════════════════════════════════════");
Console.WriteLine();

var grupate = constatari.GroupBy(c => c.Severitate)
                        .OrderByDescending(g => g.Key);

foreach (var grup in grupate)
{
    Console.WriteLine($"── {grup.Key.ToString().ToUpper()} " +
                      $"({grup.Count()} constatări) ──");

    foreach (var c in grup)
    {
        Console.WriteLine($"  [{c.Regula}] {c.Resursa}");
        Console.WriteLine($"    Problema:   {c.Descriere}");
        Console.WriteLine($"    Remediere:  {c.Remediere}");
        Console.WriteLine();
    }
}

// Statistici sumarizate
Console.WriteLine("═══════════════════════════════════════════════════");
Console.WriteLine($"Total constatări: {constatari.Count}");
Console.WriteLine($"  Critice:  {constatari.Count(c =>
    c.Severitate == Severitate.Critica)}");
Console.WriteLine($"  Ridicate: {constatari.Count(c =>
    c.Severitate == Severitate.Ridicata)}");
Console.WriteLine($"  Medii:    {constatari.Count(c =>
    c.Severitate == Severitate.Medie)}");

// ============================================================
// Modelul de date pentru configurații cloud
// ============================================================

public enum Severitate { Informational, Scazuta, Medie, Ridicata, Critica }

public record Constatare(
    string Resursa,
    string Regula,
    Severitate Severitate,
    string Descriere,
    string Remediere
);

public class StorageBucket
{
    public string Nume { get; set; } = "";
    public bool AccesPublic { get; set; }
    public bool CriptareActivata { get; set; }
    public bool LoggingAccesActivat { get; set; }
    public bool VersionareActivata { get; set; }
}

public class SecurityGroupRule
{
    public string Protocol { get; set; } = "tcp";
    public int PortStart { get; set; }
    public int PortEnd { get; set; }
    public string Sursa { get; set; } = "";  // notație CIDR
}

public class SecurityGroup
{
    public string Nume { get; set; } = "";
    public string Descriere { get; set; } = "";
    public List<SecurityGroupRule> ReguliIngress { get; set; } = [];
}

public class ContIAM
{
    public string NumeUtilizator { get; set; } = "";
    public bool AccesConsola { get; set; }        // parolă pentru consola web
    public bool EsteContDeServiciu { get; set; }  // folosit de o aplicație
    public bool MFAActivat { get; set; }
    public bool AreAccessKey { get; set; }        // cheie de acces programatic
    public int VarstaAccessKeyZile { get; set; }
    public List<string> Politici { get; set; } = [];
    public DateTime UltimaAutentificare { get; set; }
}

public class ConfiguratieCloud
{
    public List<StorageBucket> Buckets { get; set; } = [];
    public List<SecurityGroup> SecurityGroups { get; set; } = [];
    public List<ContIAM> ConturiIAM { get; set; } = [];
}

// ============================================================
// Scanner-ul de securitate
// ============================================================

public class CloudSecurityScanner
{
    private readonly List<Constatare> _constatari = [];

    public List<Constatare> Scaneaza(ConfiguratieCloud config)
    {
        _constatari.Clear();

        VerificaBuckets(config.Buckets);
        VerificaSecurityGroups(config.SecurityGroups);
        VerificaConturiIAM(config.ConturiIAM);

        return [.. _constatari.OrderByDescending(c => c.Severitate)];
    }

    private void VerificaBuckets(List<StorageBucket> buckets)
    {
        foreach (var bucket in buckets)
        {
            // Verificare: bucket public
            if (bucket.AccesPublic)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"Bucket: {bucket.Nume}",
                    Regula: "STORAGE-001",
                    Severitate: Severitate.Critica,
                    Descriere: "Bucket-ul de stocare este accesibil public. " +
                               "Datele pot fi citite de oricine de pe internet.",
                    Remediere: "Dezactivați accesul public și utilizați " +
                               "politici de acces bazate pe IAM."
                ));
            }

            // Verificare: criptare dezactivată
            if (!bucket.CriptareActivata)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"Bucket: {bucket.Nume}",
                    Regula: "STORAGE-002",
                    Severitate: Severitate.Ridicata,
                    Descriere: "Criptarea în repaus nu este activată.",
                    Remediere: "Activați criptarea server-side cu chei " +
                               "gestionate prin KMS."
                ));
            }

            // Verificare: logging dezactivat
            if (!bucket.LoggingAccesActivat)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"Bucket: {bucket.Nume}",
                    Regula: "STORAGE-003",
                    Severitate: Severitate.Medie,
                    Descriere: "Jurnalizarea accesului nu este activată. " +
                               "Nu se pot audita operațiunile pe bucket.",
                    Remediere: "Activați access logging pentru trasabilitate."
                ));
            }

            // Verificare: versionare dezactivată
            if (!bucket.VersionareActivata)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"Bucket: {bucket.Nume}",
                    Regula: "STORAGE-004",
                    Severitate: Severitate.Medie,
                    Descriere: "Versionarea obiectelor nu este activată. " +
                               "Ștergerea accidentală sau malițioasă este " +
                               "ireversibilă.",
                    Remediere: "Activați versionarea pentru protecție contra " +
                               "ștergerii accidentale."
                ));
            }
        }
    }

    private void VerificaSecurityGroups(List<SecurityGroup> groups)
    {
        // Porturi sensibile care nu trebuie expuse la internet
        var porturiSensibile = new Dictionary<int, string>
        {
            [22] = "SSH",
            [3389] = "RDP",
            [3306] = "MySQL",
            [5432] = "PostgreSQL",
            [1433] = "SQL Server",
            [27017] = "MongoDB",
            [6379] = "Redis",
            [9200] = "Elasticsearch"
        };

        foreach (var sg in groups)
        {
            foreach (var regula in sg.ReguliIngress)
            {
                bool deschisLaInternet =
                    regula.Sursa == "0.0.0.0/0" || regula.Sursa == "::/0";

                if (!deschisLaInternet) continue;

                // Verificare: port sensibil deschis la internet
                for (int port = regula.PortStart;
                     port <= regula.PortEnd;
                     port++)
                {
                    if (porturiSensibile.TryGetValue(port, out var serviciu))
                    {
                        _constatari.Add(new Constatare(
                            Resursa: $"SecurityGroup: {sg.Nume}",
                            Regula: "NETWORK-001",
                            Severitate: Severitate.Critica,
                            Descriere: $"Portul {port} ({serviciu}) este " +
                                       $"deschis la internet (0.0.0.0/0).",
                            Remediere: $"Restricționați accesul la portul " +
                                       $"{port} doar la adresele IP autorizate."
                        ));
                    }
                }

                // Verificare: interval de porturi prea larg
                int latimeInterval = regula.PortEnd - regula.PortStart;
                if (latimeInterval > 100)
                {
                    _constatari.Add(new Constatare(
                        Resursa: $"SecurityGroup: {sg.Nume}",
                        Regula: "NETWORK-002",
                        Severitate: Severitate.Ridicata,
                        Descriere: $"Interval de porturi prea larg " +
                                   $"({regula.PortStart}-{regula.PortEnd}) " +
                                   $"deschis la internet.",
                        Remediere: "Definiți reguli granulare pentru " +
                                   "fiecare port necesar."
                    ));
                }
            }
        }
    }

    private void VerificaConturiIAM(List<ContIAM> conturi)
    {
        foreach (var cont in conturi)
        {
            // Verificare: acces la consolă fără MFA
            // (MFA protejează autentificarea interactivă; cheile de
            //  acces programatic nu sunt protejate de MFA în sine)
            if (cont.AccesConsola && !cont.MFAActivat)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"IAM: {cont.NumeUtilizator}",
                    Regula: "IAM-001",
                    Severitate: Severitate.Ridicata,
                    Descriere: "Utilizatorul are acces la consolă " +
                               "(parolă) fără MFA.",
                    Remediere: "Activați MFA pentru toți utilizatorii " +
                               "cu acces la consolă."
                ));
            }

            // Verificare: cont de serviciu cu cheie de lungă durată
            if (cont.EsteContDeServiciu && cont.AreAccessKey)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"IAM: {cont.NumeUtilizator}",
                    Regula: "IAM-005",
                    Severitate: Severitate.Ridicata,
                    Descriere: "Aplicația folosește o cheie de acces " +
                               "de lungă durată.",
                    Remediere: "Folosiți un rol IAM atașat resursei " +
                               "(credențiale temporare STS) în locul " +
                               "cheilor statice."
                ));
            }

            // Verificare: access key vechi (peste 90 de zile)
            if (cont.AreAccessKey && cont.VarstaAccessKeyZile > 90)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"IAM: {cont.NumeUtilizator}",
                    Regula: "IAM-002",
                    Severitate: Severitate.Medie,
                    Descriere: $"Cheia de acces are {cont.VarstaAccessKeyZile}" +
                               $" de zile, peste limita de 90 de zile.",
                    Remediere: "Rotați cheile de acces la cel mult " +
                               "90 de zile sau eliminați-le."
                ));
            }

            // Verificare: politici excesiv de permisive
            if (cont.Politici.Any(p =>
                p.Contains('*') ||
                p.Contains("FullAccess") ||
                p.EndsWith("AdministratorAccess") ||
                p.EndsWith("PowerUserAccess")))
            {
                _constatari.Add(new Constatare(
                    Resursa: $"IAM: {cont.NumeUtilizator}",
                    Regula: "IAM-003",
                    Severitate: Severitate.Ridicata,
                    Descriere: "Contul are politici foarte largi (wildcard, " +
                               "FullAccess, Administrator sau PowerUser), " +
                               "încălcând principiul privilegiului minim.",
                    Remediere: "Înlocuiți-le cu permisiuni granulare, " +
                               "limitate la acțiunile și resursele necesare."
                ));
            }

            // Verificare: cont inactiv
            var zileInactiv =
                (DateTime.UtcNow - cont.UltimaAutentificare).Days;
            if (zileInactiv > 90)
            {
                _constatari.Add(new Constatare(
                    Resursa: $"IAM: {cont.NumeUtilizator}",
                    Regula: "IAM-004",
                    Severitate: Severitate.Medie,
                    Descriere: $"Contul nu a fost folosit de " +
                               $"{zileInactiv} de zile.",
                    Remediere: "Dezactivați sau ștergeți conturile " +
                               "inactive pentru a reduce suprafața de atac."
                ));
            }
        }
    }
}
