using System.Text.RegularExpressions;

// ============================================================
// Testare: un Dockerfile INTENȚIONAT NESIGUR și unul corectat
// ============================================================

string dockerfileNesigur = """
    FROM ubuntu:latest

    ENV DB_PASSWORD=SuperSecret123!
    ENV API_KEY=ak_live_1234567890abcdef

    RUN apt-get update
    RUN apt-get install python3 python3-yaml curl
    RUN curl -k https://example.com/script.sh | bash
    RUN chmod 777 /app

    ADD https://releases.example.com/app.tar.gz /opt/

    COPY . /app

    EXPOSE 8080
    EXPOSE 22
    EXPOSE 2375

    CMD ["python3", "/app/server.py"]
    """;

string dockerfileCorectat = """
    FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
    WORKDIR /src
    COPY SecureApi.csproj .
    RUN dotnet restore
    COPY Program.cs .
    RUN dotnet publish -c Release -o /app/publish --no-restore

    FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS final
    WORKDIR /app
    COPY --from=build /app/publish .
    USER $APP_UID
    EXPOSE 8080
    HEALTHCHECK CMD wget -qO- http://127.0.0.1:8080/ || exit 1
    ENTRYPOINT ["dotnet", "SecureApi.dll"]
    """;

var analizor = new DockerfileAnalyzer();
AfiseazaRaport("Dockerfile nesigur", analizor.Analizeaza(dockerfileNesigur));
AfiseazaRaport("Dockerfile corectat", analizor.Analizeaza(dockerfileCorectat));

static void AfiseazaRaport(string titlu, List<ProblemaDockerfile> probleme)
{
    Console.WriteLine("═══════════════════════════════════════════════════");
    Console.WriteLine($"   ANALIZA DE SECURITATE: {titlu.ToUpper()}");
    Console.WriteLine("═══════════════════════════════════════════════════");

    foreach (var p in probleme)
    {
        string indicator = p.Nivel switch
        {
            NivelRisc.Critic => "CRITIC",
            NivelRisc.Eroare => "EROARE",
            NivelRisc.Avertisment => "AVERT",
            _ => "INFO"
        };
        string locatie = p.Linie > 0 ? $"Linia {p.Linie}" : "General";

        Console.WriteLine($"[{indicator}] {p.CodRegula} ({locatie}): {p.Mesaj}");
        Console.WriteLine($"    Recomandare: {p.Recomandare}");
    }

    Console.WriteLine($"Total: {probleme.Count} probleme " +
        $"(critice: {probleme.Count(p => p.Nivel == NivelRisc.Critic)}, " +
        $"erori: {probleme.Count(p => p.Nivel == NivelRisc.Eroare)}, " +
        $"avertismente: {probleme.Count(p => p.Nivel == NivelRisc.Avertisment)})");
    Console.WriteLine();
}

// ============================================================
// Modelul de date
// ============================================================

public enum NivelRisc { Info, Avertisment, Eroare, Critic }

public record ProblemaDockerfile(
    int Linie,
    NivelRisc Nivel,
    string CodRegula,
    string Mesaj,
    string Recomandare
);

// ============================================================
// Analizorul de securitate Dockerfile
// ============================================================

public partial class DockerfileAnalyzer
{
    // Registry-uri și publisheri considerați de încredere (allowlist).
    // Imaginile fără „/” (ubuntu, alpine) sunt Docker Official Images.
    private static readonly string[] RegistryDeIncredere =
    [
        "mcr.microsoft.com/",
        "docker.io/library/",
        "cgr.dev/chainguard/"
    ];

    private readonly List<ProblemaDockerfile> _probleme = [];
    private readonly HashSet<string> _etape =
        new(StringComparer.OrdinalIgnoreCase);

    // FROM [--platform=...] imagine [AS nume]
    [GeneratedRegex(@"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?",
        RegexOptions.IgnoreCase)]
    private static partial Regex RegexFrom();

    // curl/wget ... | sh (sau bash, zsh, dash), eventual cu sudo
    [GeneratedRegex(@"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")]
    private static partial Regex RegexPipeInShell();

    public List<ProblemaDockerfile> Analizeaza(string continutDockerfile)
    {
        _probleme.Clear();
        _etape.Clear();
        var linii = continutDockerfile.Split('\n');

        // Utilizatorul efectiv al etapei curente; null = root (implicit)
        string? utilizatorEtapaCurenta = null;
        bool areHealthcheck = false;

        for (int i = 0; i < linii.Length; i++)
        {
            int numarLinie = i + 1;
            string linie = linii[i].Trim();

            // Ignorăm comentariile și liniile goale
            if (string.IsNullOrWhiteSpace(linie) || linie.StartsWith('#'))
                continue;

            if (EsteInstructiune(linie, "FROM"))
            {
                VerificaFROM(linie, numarLinie);
                utilizatorEtapaCurenta = null;  // fiecare etapă pornește ca root
            }

            VerificaRUN(linie, numarLinie);
            VerificaCOPY(linie, numarLinie);
            VerificaADD(linie, numarLinie);
            VerificaENV(linie, numarLinie);
            VerificaEXPOSE(linie, numarLinie);

            if (EsteInstructiune(linie, "USER"))
                utilizatorEtapaCurenta = linie[4..].Trim();

            if (EsteInstructiune(linie, "HEALTHCHECK"))
                areHealthcheck = true;
        }

        // Contează doar ultimul USER din ULTIMA etapă (imaginea finală)
        if (EsteRoot(utilizatorEtapaCurenta))
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: 0,
                Nivel: NivelRisc.Critic,
                CodRegula: "DKR-001",
                Mesaj: "Etapa finală rulează ca root (lipsește USER " +
                       "sau utilizatorul este root/UID 0).",
                Recomandare: "Imagini .NET: USER $APP_UID. Debian/Ubuntu: " +
                             "RUN useradd -r -u 10001 appuser. Alpine: " +
                             "RUN adduser -D -u 10001 appuser. Apoi USER."
            ));
        }

        if (!areHealthcheck)
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: 0,
                Nivel: NivelRisc.Info,
                CodRegula: "DKR-010",
                Mesaj: "Lipsește instrucțiunea HEALTHCHECK.",
                Recomandare: "Adăugați HEALTHCHECK (sau probe în " +
                             "Kubernetes) pentru monitorizarea stării."
            ));
        }

        return [.. _probleme.OrderByDescending(p => p.Nivel)
                            .ThenBy(p => p.Linie)];
    }

    private static bool EsteInstructiune(string linie, string instructiune) =>
        linie.StartsWith(instructiune + " ", StringComparison.OrdinalIgnoreCase);

    private static bool EsteRoot(string? utilizator)
    {
        if (string.IsNullOrWhiteSpace(utilizator)) return true;
        string nume = utilizator.Split(':')[0];  // USER nume:grup
        return nume.Equals("root", StringComparison.OrdinalIgnoreCase) ||
               nume == "0";
    }

    private void VerificaFROM(string linie, int numarLinie)
    {
        var match = RegexFrom().Match(linie);
        if (!match.Success) return;

        string imagine = match.Groups[1].Value;
        bool etapaAnterioara = _etape.Contains(imagine);
        if (match.Groups[2].Success)
            _etape.Add(match.Groups[2].Value);

        // FROM <etapă anterioară> sau FROM scratch: nimic de verificat
        if (etapaAnterioara ||
            imagine.Equals("scratch", StringComparison.OrdinalIgnoreCase))
            return;

        // Digest-ul fixează conținutul exact
        if (!imagine.Contains("@sha256:"))
        {
            // Tag-ul este după ultimul „:” din ultima componentă a căii
            string ultimaComponenta = imagine[(imagine.LastIndexOf('/') + 1)..];
            int pozitieTag = ultimaComponenta.LastIndexOf(':');
            string? tag = pozitieTag >= 0
                ? ultimaComponenta[(pozitieTag + 1)..]
                : null;

            if (tag is null || tag.Equals("latest",
                    StringComparison.OrdinalIgnoreCase))
            {
                _probleme.Add(new ProblemaDockerfile(
                    Linie: numarLinie,
                    Nivel: NivelRisc.Eroare,
                    CodRegula: "DKR-002",
                    Mesaj: $"Imaginea '{imagine}' folosește tag-ul " +
                           "'latest' sau nu are tag.",
                    Recomandare: "Folosiți un tag explicit (ex: " +
                                 "'aspnet:10.0-alpine') și, pentru " +
                                 "reproductibilitate, digest-ul @sha256."
                ));
            }
        }

        // Proveniența: allowlist de registry-uri și publisheri
        bool imagineOficialaDockerHub = !imagine.Contains('/');
        bool deIncredere = imagineOficialaDockerHub ||
            RegistryDeIncredere.Any(r =>
                imagine.StartsWith(r, StringComparison.OrdinalIgnoreCase));

        if (!deIncredere)
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: numarLinie,
                Nivel: NivelRisc.Avertisment,
                CodRegula: "DKR-003",
                Mesaj: $"Imaginea '{imagine}' nu provine dintr-un " +
                       "registry sau de la un publisher aprobat.",
                Recomandare: "Folosiți imagini oficiale; pentru altele, " +
                             "verificați publisherul și semnătura (cosign)."
            ));
        }
    }

    private void VerificaRUN(string linie, int numarLinie)
    {
        if (!EsteInstructiune(linie, "RUN")) return;

        // Instalare fără curățarea cache-ului
        if ((linie.Contains("apt-get install") ||
             linie.Contains("apt install")) &&
            !linie.Contains("rm -rf /var/lib/apt/lists") &&
            !linie.Contains("apt-get clean"))
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: numarLinie,
                Nivel: NivelRisc.Avertisment,
                CodRegula: "DKR-004",
                Mesaj: "Instalare APT fără curățarea cache-ului.",
                Recomandare: "Adăugați '&& rm -rf /var/lib/apt/lists/*' " +
                             "în aceeași instrucțiune RUN."
            ));
        }

        // apt-get install fără confirmare automată (build interactiv).
        // Se verifică opțiunile ca token-uri separate, ca „python3-yaml”
        // să nu fie confundat cu „-y”.
        if (linie.Contains("apt-get install"))
        {
            var tokenuri = linie.Split(' ',
                StringSplitOptions.RemoveEmptyEntries);
            bool areConfirmare = tokenuri.Any(t =>
                t is "--yes" or "--assume-yes" ||
                (t.StartsWith('-') && !t.StartsWith("--") && t.Contains('y')));

            if (!areConfirmare)
            {
                _probleme.Add(new ProblemaDockerfile(
                    Linie: numarLinie,
                    Nivel: NivelRisc.Avertisment,
                    CodRegula: "DKR-005",
                    Mesaj: "apt-get install fără -y poate bloca build-ul " +
                           "așteptând confirmare.",
                    Recomandare: "Folosiți 'apt-get install -y " +
                                 "--no-install-recommends'."
                ));
            }
        }

        // Descărcare fără verificarea certificatului TLS
        if ((linie.Contains("curl") || linie.Contains("wget")) &&
            (linie.Contains(" -k") || linie.Contains("--insecure") ||
             linie.Contains("--no-check-certificate")))
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: numarLinie,
                Nivel: NivelRisc.Eroare,
                CodRegula: "DKR-006",
                Mesaj: "Descărcare fără verificarea certificatului TLS " +
                       "(vulnerabil la MITM).",
                Recomandare: "Eliminați -k/--insecure/" +
                             "--no-check-certificate."
            ));
        }

        // Script descărcat și executat direct (curl | bash)
        if (RegexPipeInShell().IsMatch(linie))
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: numarLinie,
                Nivel: NivelRisc.Critic,
                CodRegula: "DKR-013",
                Mesaj: "Script descărcat și executat direct " +
                       "(curl/wget | sh), fără nicio verificare.",
                Recomandare: "Descărcați fișierul, verificați suma de " +
                             "control sau semnătura, apoi executați-l."
            ));
        }

        // chmod 777
        if (linie.Contains("chmod 777") || linie.Contains("chmod -R 777"))
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: numarLinie,
                Nivel: NivelRisc.Eroare,
                CodRegula: "DKR-007",
                Mesaj: "chmod 777 acordă permisiuni complete tuturor " +
                       "utilizatorilor.",
                Recomandare: "Folosiți permisiuni restrictive " +
                             "(ex: chmod 550 pentru executabile)."
            ));
        }
    }

    private void VerificaCOPY(string linie, int numarLinie)
    {
        if (!EsteInstructiune(linie, "COPY")) return;

        // COPY . . sau COPY . /cale: copiază tot contextul de build
        if (Regex.IsMatch(linie, @"^COPY\s+\.\s+\S+", RegexOptions.IgnoreCase))
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: numarLinie,
                Nivel: NivelRisc.Avertisment,
                CodRegula: "DKR-008",
                Mesaj: "COPY . copiază întregul context de build, " +
                       "inclusiv .git, .env sau chei.",
                Recomandare: "Copiați doar fișierele necesare și " +
                             "folosiți .dockerignore."
            ));
        }
    }

    private void VerificaADD(string linie, int numarLinie)
    {
        if (!EsteInstructiune(linie, "ADD")) return;

        if (linie.Contains("http://") || linie.Contains("https://"))
        {
            _probleme.Add(new ProblemaDockerfile(
                Linie: numarLinie,
                Nivel: NivelRisc.Eroare,
                CodRegula: "DKR-009",
                Mesaj: "ADD cu URL descarcă fișiere fără verificarea " +
                       "integrității.",
                Recomandare: "Folosiți ADD --checksum=sha256:..., sau " +
                             "RUN curl + verificarea sumei de control."
            ));
        }
    }

    private void VerificaENV(string linie, int numarLinie)
    {
        if (!EsteInstructiune(linie, "ENV")) return;

        string[] tipareSecrete =
        [
            "PASSWORD", "SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY",
            "CREDENTIALS", "DB_PASS", "AWS_SECRET"
        ];

        foreach (var tipar in tipareSecrete)
        {
            if (linie.Contains(tipar, StringComparison.OrdinalIgnoreCase))
            {
                _probleme.Add(new ProblemaDockerfile(
                    Linie: numarLinie,
                    Nivel: NivelRisc.Critic,
                    CodRegula: "DKR-011",
                    Mesaj: $"Posibil secret ({tipar}) scris în imagine; " +
                           "valoarea rămâne vizibilă în istoria imaginii.",
                    Recomandare: "La rulare: fișiere montate (Docker/" +
                                 "Kubernetes Secrets, Vault). La build: " +
                                 "RUN --mount=type=secret."
                ));
                break;
            }
        }
    }

    private void VerificaEXPOSE(string linie, int numarLinie)
    {
        if (!EsteInstructiune(linie, "EXPOSE")) return;

        var porturiPericuloase = new Dictionary<int, string>
        {
            [22] = "SSH",
            [23] = "Telnet",
            [2375] = "Docker API necriptat",
            [2376] = "Docker API cu TLS",
            [10250] = "Kubelet API"
        };

        foreach (Match m in Regex.Matches(linie, @"\d+"))
        {
            if (int.TryParse(m.Value, out int port) &&
                porturiPericuloase.TryGetValue(port, out var descriere))
            {
                _probleme.Add(new ProblemaDockerfile(
                    Linie: numarLinie,
                    Nivel: NivelRisc.Eroare,
                    CodRegula: "DKR-012",
                    Mesaj: $"Portul {port} ({descriere}) expus într-un " +
                           "container de aplicație.",
                    Recomandare: "Eliminați EXPOSE pentru porturile " +
                                 "de management."
                ));
            }
        }
    }
}
