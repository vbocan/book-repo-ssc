using System.Text;

public enum Response { Yes, No, Partial, NotApplicable }

public enum Severity { Critical, High, Medium, Low }

public record AuditQuestion(
    string Id,
    string Text,
    Severity Severity,
    string Recommendation);

public record AuditCategory(
    string Name,
    string Description,
    IReadOnlyList<AuditQuestion> Questions);

public record QuestionResult(
    AuditQuestion Question,
    Response Response);

public record CategoryResult(
    AuditCategory Category,
    IReadOnlyList<QuestionResult> Results)
{
    // null = nicio întrebare aplicabilă (categoria nu se evaluează)
    public double? Score => Scoring.Score(Results);
    public string Rating => Scoring.Rating(Score);
}

public static class Scoring
{
    // Da = 100, Parțial = 50, Nu = 0; „Nu se aplică” este exclus.
    // Aceeași regulă pentru categorii și pentru scorul global.
    public static double? Score(IEnumerable<QuestionResult> results)
    {
        var applicable = results
            .Where(r => r.Response != Response.NotApplicable)
            .ToList();
        if (applicable.Count == 0) return null;

        return applicable.Average(r => r.Response switch
        {
            Response.Yes => 100.0,
            Response.Partial => 50.0,
            _ => 0.0
        });
    }

    public static string Rating(double? score) => score switch
    {
        null => "Neevaluat",
        >= 90 => "Excelent",
        >= 75 => "Bun",
        >= 50 => "Acceptabil",
        >= 25 => "Insuficient",
        _ => "Critic"
    };
}

public static class AuditData
{
    public static List<AuditCategory> GetCategories() =>
    [
        new("Securitate perimetrală", "Controale de securitate la nivelul perimetrului exterior",
        [
            new("P01", "Există gard perimetral de minimum 2,5m înălțime?",
                Severity.High,
                "Instalați gard perimetral conform standardelor de securitate fizică."),
            new("P02", "Perimetrul este iluminat corespunzător pe timp de noapte (min. 10 lux)?",
                Severity.Medium,
                "Instalați iluminat perimetral cu senzori de mișcare."),
            new("P03", "Există bariere anti-vehicul (bollard-uri) la punctele de acces?",
                Severity.Medium,
                "Instalați bollard-uri sau bariere retractabile la intrări."),
            new("P04", "Există zonă liberă (clear zone) între gard și clădire?",
                Severity.Low,
                "Eliminați vegetația și obiectele care oferă ascunzătoare."),
            new("P05", "Perimetrul este monitorizat video 24/7?",
                Severity.High,
                "Instalați camere CCTV cu acoperire completă a perimetrului.")
        ]),

        new("Securitate clădire", "Controale la nivelul clădirii și al punctelor de acces",
        [
            new("B01", "Intrările sunt controlate cu sistem electronic de acces?",
                Severity.Critical,
                "Implementați control acces electronic cu smart card-uri."),
            new("B02", "Există sistem mantrap (sas) la intrarea în zonele securizate?",
                Severity.High,
                "Instalați sisteme mantrap cu uși interblocate."),
            new("B03", "Ușile exterioare sunt din materiale rezistente la forțare?",
                Severity.Medium,
                "Înlocuiți ușile vulnerabile cu uși din oțel certificate."),
            new("B04", "Există procedură documentată de gestionare a vizitatorilor?",
                Severity.High,
                "Implementați politică de vizitatori: pre-înregistrare, escortă, badge temporar."),
            new("B05", "Ferestrele din zonele sensibile au protecție anti-efracție?",
                Severity.Medium,
                "Aplicați folie de securitate sau instalați ferestre anti-efracție.")
        ]),

        new("Sala de servere", "Controale specifice pentru camerele cu echipamente IT",
        [
            new("S01", "Accesul în sala de servere necesită autentificare multifactor?",
                Severity.Critical,
                "Implementați MFA fizic: card + PIN sau card + biometrie."),
            new("S02", "Rack-urile au încuietori funcționale și accesul este jurnalizat?",
                Severity.High,
                "Instalați încuietori electronice cu audit trail pe rack-uri."),
            new("S03", "Există sistem de suprimare a incendiilor adecvat (gaz, nu apă)?",
                Severity.Critical,
                "Instalați sistem de stingere cu agent curat (FK-5-1-12, gaz inert)."),
            new("S04", "Pardoseala ridicată este monitorizată cu senzori de scurgeri?",
                Severity.High,
                "Instalați cabluri senzor pentru detectarea apei sub pardoseala ridicată."),
            new("S05", "Există configurație hot/cold aisle cu containment?",
                Severity.Medium,
                "Implementați separarea culoarelor cald/rece cu panouri de containment.")
        ]),

        new("Securitate echipamente", "Controale privind protecția echipamentelor IT",
        [
            new("E01", "Există procedură de eliminare securizată a mediilor de stocare?",
                Severity.Critical,
                "Implementați procedură conformă NIST SP 800-88 (clear/purge/destroy)."),
            new("E02", "Echipamentele au sigilii tamper-evident verificate periodic?",
                Severity.Medium,
                "Aplicați sigilii pe carcasele serverelor și verificați-le lunar."),
            new("E03", "Există inventar actualizat al tuturor echipamentelor (asset tracking)?",
                Severity.High,
                "Implementați sistem de asset tracking cu RFID sau cod de bare."),
            new("E04", "Laptopurile și dispozitivele mobile au criptare completă a discului?",
                Severity.Critical,
                "Activați BitLocker/FileVault pe toate dispozitivele mobile."),
            new("E05", "Echipamentele sunt achiziționate exclusiv de la distribuitori autorizați?",
                Severity.High,
                "Stabiliți politică de achiziție doar prin canale autorizate de furnizori.")
        ]),

        new("Protecția mediului", "Controale de protecție a mediului fizic",
        [
            new("M01", "Temperatura și umiditatea sunt monitorizate continuu?",
                Severity.High,
                "Instalați senzori de temperatură și umiditate cu alerte automate."),
            new("M02", "Există sistem UPS funcțional și testat periodic?",
                Severity.Critical,
                "Instalați UPS dimensionat corespunzător și testați-l lunar."),
            new("M03", "Generatoarele diesel sunt testate sub sarcină cel puțin lunar?",
                Severity.High,
                "Stabiliți program de testare lunară a generatoarelor sub sarcină."),
            new("M04", "Există protecție la supratensiuni (SPD) pe liniile de alimentare?",
                Severity.High,
                "Instalați supresoare de supratensiuni pe toate liniile de alimentare."),
            new("M05", "Există sistem de detectare a fumului de tip aspirație (VESDA)?",
                Severity.Medium,
                "Instalați detectoare de fum de înaltă sensibilitate (VESDA).")
        ]),

        new("Control acces", "Controale privind managementul accesului fizic",
        [
            new("A01", "Drepturile de acces fizic sunt revizuite periodic (cel puțin trimestrial)?",
                Severity.High,
                "Implementați revizuire trimestrială a drepturilor de acces fizic."),
            new("A02", "Există procedură de revocare imediată a accesului la terminarea contractului?",
                Severity.Critical,
                "Integrați revocarea accesului fizic în procesul de offboarding HR."),
            new("A03", "Retenția înregistrărilor CCTV are o durată justificată și ștergere automată?",
                Severity.High,
                "Documentați durata de retenție (vezi cap. 15) și configurați ștergerea automată."),
            new("A04", "Sistemul de alarme este monitorizat 24/7 de un centru specializat?",
                Severity.High,
                "Contractați servicii de monitorizare 24/7 pentru alarme."),
            new("A05", "Există detectoare anti-tailgating la punctele de acces critice?",
                Severity.Medium,
                "Instalați senzori optici sau turnichete la intrările în zone securizate.")
        ])
    ];
}

public class AuditEngine
{
    private readonly List<AuditCategory> _categories;
    private readonly List<CategoryResult> _results = [];
    private string _organizationName = "";
    private string _auditorName = "";
    private DateTime _auditDate;

    public AuditEngine(List<AuditCategory> categories)
    {
        _categories = categories;
    }

    public void Run()
    {
        PrintHeader();
        CollectMetadata();

        foreach (var category in _categories)
        {
            var result = AuditCategory(category);
            _results.Add(result);
        }

        GenerateReport();
    }

    private void PrintHeader()
    {
        Console.WriteLine("╔══════════════════════════════════════════════════╗");
        Console.WriteLine("║        AUDIT DE SECURITATE FIZICĂ (v1.1)         ║");
        Console.WriteLine("║   ISO/IEC 27001:2022, Anexa A, controalele 7.x   ║");
        Console.WriteLine("╚══════════════════════════════════════════════════╝");
        Console.WriteLine();
    }

    private void CollectMetadata()
    {
        Console.Write("Numele organizației: ");
        _organizationName = Console.ReadLine() ?? "Necunoscut";

        Console.Write("Numele auditorului: ");
        _auditorName = Console.ReadLine() ?? "Necunoscut";

        _auditDate = DateTime.Now;
        Console.WriteLine($"Data auditului: {_auditDate:yyyy-MM-dd}");
        Console.WriteLine();
    }

    private CategoryResult AuditCategory(AuditCategory category)
    {
        Console.WriteLine($"── {category.Name.ToUpper()} ──");
        Console.WriteLine($"   {category.Description}");
        Console.WriteLine();

        var results = new List<QuestionResult>();

        foreach (var question in category.Questions)
        {
            Console.WriteLine($"  [{question.Id}] {question.Text}");
            Console.Write(
                $"  Severitate: {question.Severity} | " +
                "Răspuns (D=Da, N=Nu, P=Parțial, X=Nu se aplică): ");

            var response = ReadResponse();
            results.Add(new QuestionResult(question, response));
            Console.WriteLine();
        }

        var categoryResult = new CategoryResult(category, results);
        Console.WriteLine(
            $"  ► Scor {category.Name}: " +
            $"{categoryResult.Score:F0}% ({categoryResult.Rating})");
        Console.WriteLine();

        return categoryResult;
    }

    private static Response ReadResponse()
    {
        while (true)
        {
            // Console.ReadKey aruncă excepție când intrarea este
            // redirecționată (de ex. „dotnet run < raspunsuri.txt”),
            // așa că în acel caz citim caracter cu caracter din stdin.
            char key;
            if (Console.IsInputRedirected)
            {
                int c = Console.In.Read();
                if (c == -1) return Response.NotApplicable;
                key = (char)c;
            }
            else
            {
                key = Console.ReadKey(true).KeyChar;
            }

            switch (char.ToUpper(key))
            {
                case 'D': Console.WriteLine("Da"); return Response.Yes;
                case 'N': Console.WriteLine("Nu"); return Response.No;
                case 'P': Console.WriteLine("Parțial"); return Response.Partial;
                case 'X': Console.WriteLine("Nu se aplică"); return Response.NotApplicable;
            }
        }
    }

    private void GenerateReport()
    {
        var sb = new StringBuilder();

        sb.AppendLine();
        sb.AppendLine("╔══════════════════════════════════════════════════╗");
        sb.AppendLine("║        RAPORT DE AUDIT DE SECURITATE FIZICĂ      ║");
        sb.AppendLine("╚══════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"  Organizație: {_organizationName}");
        sb.AppendLine($"  Auditor:     {_auditorName}");
        sb.AppendLine($"  Data:        {_auditDate:yyyy-MM-dd HH:mm}");
        sb.AppendLine();

        // Scor global: aceeași regulă ca pe categorii
        double? globalScore = Scoring.Score(
            _results.SelectMany(c => c.Results));
        string globalRating = Scoring.Rating(globalScore).ToUpper();

        sb.AppendLine("── SCOR GLOBAL ──");
        sb.AppendLine();
        sb.AppendLine(globalScore is null
            ? $"  n/a: {globalRating}"
            : $"  {globalScore:F0}%: {globalRating}");
        sb.AppendLine();
        sb.AppendLine(GenerateScoreBar(globalScore ?? 0));
        sb.AppendLine();

        // Scoruri pe categorii
        sb.AppendLine("── SCORURI PE CATEGORII ──");
        sb.AppendLine();

        foreach (var result in _results.OrderBy(r => r.Score ?? 101))
        {
            var score = result.Score is null
                ? "  n/a" : $"{result.Score,5:F0}%";
            sb.AppendLine(
                $"  {result.Category.Name,-28} {score} ({result.Rating})");
        }

        sb.AppendLine();

        // Constatări critice
        var critical = _results
            .SelectMany(c => c.Results
                .Where(r => r.Response == Response.No
                    && r.Question.Severity <= Severity.High)
                .Select(r => (Category: c.Category.Name, r.Question)))
            .OrderBy(x => x.Question.Severity)
            .ToList();

        if (critical.Count > 0)
        {
            sb.AppendLine("── CONSTATĂRI CRITICE ──");
            sb.AppendLine();

            foreach (var (category, question) in critical)
            {
                sb.AppendLine(
                    $"  [{question.Severity.ToString().ToUpper(),-8}] " +
                    $"[{question.Id}] {question.Text}");
                sb.AppendLine(
                    $"             Categorie: {category}");
                sb.AppendLine(
                    $"             Recomandare: {question.Recommendation}");
                sb.AppendLine();
            }
        }

        // Statistici
        var totalQuestions = _results.SelectMany(c => c.Results).Count();
        var yesCount = _results.SelectMany(c => c.Results)
            .Count(r => r.Response == Response.Yes);
        var noCount = _results.SelectMany(c => c.Results)
            .Count(r => r.Response == Response.No);
        var partialCount = _results.SelectMany(c => c.Results)
            .Count(r => r.Response == Response.Partial);
        var naCount = _results.SelectMany(c => c.Results)
            .Count(r => r.Response == Response.NotApplicable);

        sb.AppendLine("── STATISTICI ──");
        sb.AppendLine();
        sb.AppendLine($"  Total întrebări:   {totalQuestions}");
        sb.AppendLine($"  Conforme (Da):     {yesCount}");
        sb.AppendLine($"  Neconforme (Nu):   {noCount}");
        sb.AppendLine($"  Parțial conforme:  {partialCount}");
        sb.AppendLine($"  Nu se aplică:      {naCount}");
        sb.AppendLine();
        sb.AppendLine(
            "  Referință: ISO/IEC 27001:2022, Anexa A, " +
            "controalele 7.1–7.14 (controale fizice)");

        Console.Write(sb.ToString());
    }

    private static string GenerateScoreBar(double score)
    {
        const int width = 40;
        int filled = (int)(score / 100.0 * width);
        int empty = width - filled;

        return $"  [{new string('█', filled)}{new string('░', empty)}]";
    }
}

public class Program
{
    public static void Main()
    {
        var categories = AuditData.GetCategories();
        var engine = new AuditEngine(categories);
        engine.Run();
    }
}
