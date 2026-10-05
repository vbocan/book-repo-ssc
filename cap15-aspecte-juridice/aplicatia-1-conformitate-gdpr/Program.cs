using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace GdprComplianceChecker;

public enum ComplianceStatus
{
    Pass,
    Warning,
    Fail
}

public record ComplianceCheck(
    string Area,
    string Description,
    ComplianceStatus Status,
    string Details,
    string Recommendation);

public record ApplicationProfile(
    string Name,
    bool HasConsentMechanism,
    bool ConsentIsGranular,
    bool ConsentIsWithdrawable,
    bool PreTickedBoxes,
    List<string> DataFieldsCollected,
    List<string> DataFieldsRequired,
    bool EncryptsDataAtRest,
    bool EncryptsDataInTransit,
    string EncryptionAlgorithm,
    bool HasRetentionPolicy,
    int RetentionDays,
    bool AutoDeletesExpiredData,
    bool HasBreachNotificationProcedure,
    int BreachNotificationHours,
    bool HasDpo,
    bool IsPublicAuthority,           // autoritate sau organism public
    bool SystematicMonitoring,        // monitorizare regulată și sistematică
                                      // (de ex. urmărire și profilare online)
    bool ProcessesSensitiveData,      // categorii speciale (art. 9) sau art. 10
    bool ProfilesUsers,
    bool AutomatedDecisionsWithLegalEffect, // decizii automate cu efecte juridice
    bool LargeScaleProcessing,
    bool MonitorsPublicAreas,         // supraveghere video a spațiilor publice
    bool HasCompletedDpia,
    int EstimatedDataSubjects);

public class GdprComplianceChecker
{
    private readonly ApplicationProfile _profile;
    private readonly List<ComplianceCheck> _results = [];

    public GdprComplianceChecker(ApplicationProfile profile)
    {
        _profile = profile;
    }

    public List<ComplianceCheck> Evaluate()
    {
        _results.Clear();
        CheckConsent();
        CheckDataMinimization();
        CheckEncryption();
        CheckRetentionPolicy();
        CheckBreachNotification();
        CheckDpo();
        CheckDpia();
        return _results;
    }

    private void CheckConsent()
    {
        if (!_profile.HasConsentMechanism)
        {
            _results.Add(new ComplianceCheck(
                "Consimțământ", "Mecanism de consimțământ",
                ComplianceStatus.Fail,
                "Nu există mecanism de obținere a consimțământului.",
                "Implementați un mecanism de consimțământ conform Art. 7 GDPR: " +
                "liber exprimat, specific, informat, lipsit de ambiguitate."));
            return;
        }

        if (_profile.PreTickedBoxes)
        {
            _results.Add(new ComplianceCheck(
                "Consimțământ", "Căsuțe bifate în prealabil",
                ComplianceStatus.Fail,
                "Căsuțele bifate în prealabil nu constituie consimțământ " +
                "valid (C-673/17).",
                "Eliminați căsuțele bifate în prealabil. Consimțământul " +
                "necesită o acțiune afirmativă clară din partea utilizatorului."));
            return;
        }

        if (!_profile.ConsentIsGranular || !_profile.ConsentIsWithdrawable)
        {
            var issues = new List<string>();
            if (!_profile.ConsentIsGranular)
                issues.Add("nu este granular (per scop)");
            if (!_profile.ConsentIsWithdrawable)
                issues.Add("retragerea nu este la fel de ușoară ca acordarea");

            _results.Add(new ComplianceCheck(
                "Consimțământ", "Calitatea consimțământului",
                ComplianceStatus.Warning,
                $"Consimțământ: {string.Join("; ", issues)}.",
                "Art. 7(3): retragerea trebuie să fie la fel de ușoară " +
                "ca acordarea. Considerentul 43: granularitate per scop."));
            return;
        }

        _results.Add(new ComplianceCheck(
            "Consimțământ", "Mecanism de consimțământ",
            ComplianceStatus.Pass,
            "Consimțământ granular, care poate fi retras, fără căsuțe " +
            "bifate în prealabil.",
            "Mențineți evidența consimțământurilor (Art. 7(1))."));
    }

    private void CheckDataMinimization()
    {
        var unnecessaryFields = _profile.DataFieldsCollected
            .Except(_profile.DataFieldsRequired).ToList();

        if (unnecessaryFields.Count == 0)
        {
            _results.Add(new ComplianceCheck(
                "Minimizarea datelor", "Câmpuri colectate vs. necesare",
                ComplianceStatus.Pass,
                "Toate câmpurile colectate sunt necesare scopului declarat.",
                "Reevaluați periodic necesitatea fiecărui câmp."));
            return;
        }

        double ratio = (double)unnecessaryFields.Count
            / _profile.DataFieldsCollected.Count;
        var status = ratio > 0.3
            ? ComplianceStatus.Fail : ComplianceStatus.Warning;

        _results.Add(new ComplianceCheck(
            "Minimizarea datelor", "Câmpuri colectate vs. necesare",
            status,
            $"{unnecessaryFields.Count} câmpuri posibil nenecesare: " +
            $"{string.Join(", ", unnecessaryFields)}.",
            "Art. 5(1)(c): datele trebuie să fie adecvate, relevante " +
            "și limitate la ceea ce este necesar scopului prelucrării."));
    }

    private void CheckEncryption()
    {
        if (!_profile.EncryptsDataAtRest && !_profile.EncryptsDataInTransit)
        {
            _results.Add(new ComplianceCheck(
                "Criptare", "Protecția datelor personale",
                ComplianceStatus.Warning,
                "Datele nu sunt criptate nici la stocare, nici în tranzit.",
                "Art. 32 dă criptarea ca exemplu de măsură adecvată; " +
                "lipsa ei trebuie justificată prin analiza de risc."));
            return;
        }

        if (!_profile.EncryptsDataAtRest || !_profile.EncryptsDataInTransit)
        {
            var missing = !_profile.EncryptsDataAtRest
                ? "la stocare" : "în tranzit";
            _results.Add(new ComplianceCheck(
                "Criptare", "Protecția datelor personale",
                ComplianceStatus.Warning,
                $"Criptare lipsă {missing}.",
                $"Completați protecția prin criptare {missing}. " +
                "Art. 32 recomandă criptarea ca măsură de securitate."));
            return;
        }

        // MD5 și SHA-1 sunt funcții hash, nu algoritmi de criptare;
        // aici căutăm doar cifruri învechite (verificare simplificată).
        var weakAlgorithms = new[] { "DES", "3DES", "RC4" };
        if (weakAlgorithms.Any(a => _profile.EncryptionAlgorithm
            .Contains(a, StringComparison.OrdinalIgnoreCase)))
        {
            _results.Add(new ComplianceCheck(
                "Criptare", "Algoritm de criptare",
                ComplianceStatus.Warning,
                $"Algoritmul {_profile.EncryptionAlgorithm} este considerat slab.",
                "Migrați la AES-GCM (simetric) și TLS 1.2+ " +
                "(de preferat TLS 1.3). Vezi capitolele 5 și 6."));
            return;
        }

        _results.Add(new ComplianceCheck(
            "Criptare", "Protecția datelor personale",
            ComplianceStatus.Pass,
            $"Criptare la stocare și în tranzit cu {_profile.EncryptionAlgorithm}.",
            "Monitorizați evoluția standardelor criptografice."));
    }

    private void CheckRetentionPolicy()
    {
        if (!_profile.HasRetentionPolicy)
        {
            _results.Add(new ComplianceCheck(
                "Politica de retenție", "Limitarea stocării",
                ComplianceStatus.Fail,
                "Nu există o politică de retenție a datelor.",
                "Art. 5(1)(e): datele nu trebuie păstrate mai mult decât " +
                "este necesar scopului. Definiți perioade de retenție " +
                "per categorie de date."));
            return;
        }

        if (!_profile.AutoDeletesExpiredData)
        {
            _results.Add(new ComplianceCheck(
                "Politica de retenție", "Ștergere automată",
                ComplianceStatus.Warning,
                "Retenție definită " +
                $"({DaysText(_profile.RetentionDays)}), " +
                "dar fără ștergere automată.",
                "Implementați mecanisme automate de ștergere/anonimizare " +
                "la expirarea perioadei de retenție."));
            return;
        }

        _results.Add(new ComplianceCheck(
            "Politica de retenție", "Limitarea stocării",
            ComplianceStatus.Pass,
            $"Retenție de {DaysText(_profile.RetentionDays)}, cu ștergere automată.",
            "Verificați periodic că ștergerea funcționează corect."));
    }

    // „1 zi”, „15 zile”, „30 de zile”, „101 zile”, „365 de zile”:
    // în română, „de” apare când ultimele două cifre formează
    // 00 sau un număr >= 20
    private static string DaysText(int days) =>
        days == 1 ? "1 zi"
        : days != 0 && (days % 100 == 0 || days % 100 >= 20)
            ? $"{days} de zile"
            : $"{days} zile";

    private void CheckBreachNotification()
    {
        if (!_profile.HasBreachNotificationProcedure)
        {
            _results.Add(new ComplianceCheck(
                "Notificarea breșelor", "Procedură de notificare",
                ComplianceStatus.Fail,
                "Nu există procedură de notificare a breșelor.",
                "Art. 33: notificarea autorității în 72h. Art. 34: " +
                "comunicarea către persoanele vizate dacă riscul e ridicat. " +
                "Vezi capitolul 13 pentru răspunsul la incidente."));
            return;
        }

        if (_profile.BreachNotificationHours > 72)
        {
            _results.Add(new ComplianceCheck(
                "Notificarea breșelor", "Termenul de notificare",
                ComplianceStatus.Fail,
                $"Termenul de notificare ({_profile.BreachNotificationHours}h) " +
                "depășește limita de 72h.",
                "Reduceți termenul la maximum 72h conform Art. 33(1)."));
            return;
        }

        _results.Add(new ComplianceCheck(
            "Notificarea breșelor", "Procedură de notificare",
            ComplianceStatus.Pass,
            $"Procedură definită cu notificare în {_profile.BreachNotificationHours}h.",
            "Testați periodic procedura prin exerciții simulate."));
    }

    private void CheckDpo()
    {
        // Art. 37(1) GDPR: DPO obligatoriu pentru (a) autorități publice,
        // (b) activități principale de monitorizare regulată și
        // sistematică pe scară largă, (c) prelucrare pe scară largă
        // de categorii speciale de date. Scara largă singură NU ajunge.
        var reasons = new List<string>();
        if (_profile.IsPublicAuthority)
            reasons.Add("autoritate publică");
        if (_profile.LargeScaleProcessing && _profile.SystematicMonitoring)
            reasons.Add("monitorizare sistematică pe scară largă");
        if (_profile.LargeScaleProcessing && _profile.ProcessesSensitiveData)
            reasons.Add("date sensibile pe scară largă");
        bool dpoRequired = reasons.Count > 0;

        if (dpoRequired && !_profile.HasDpo)
        {
            _results.Add(new ComplianceCheck(
                "DPO", "Responsabil cu protecția datelor",
                ComplianceStatus.Fail,
                $"DPO obligatoriu (art. 37(1)): {string.Join("; ", reasons)}.",
                "Desemnați un DPO (angajat sau extern) și comunicați " +
                "datele de contact autorității (art. 37(7))."));
            return;
        }

        if (!dpoRequired && !_profile.HasDpo)
        {
            _results.Add(new ComplianceCheck(
                "DPO", "Responsabil cu protecția datelor",
                ComplianceStatus.Warning,
                "DPO nu este obligatoriu, dar este recomandat.",
                "Chiar dacă nu este obligatoriu, un DPO demonstrează " +
                "angajamentul organizației față de protecția datelor."));
            return;
        }

        _results.Add(new ComplianceCheck(
            "DPO", "Responsabil cu protecția datelor",
            ComplianceStatus.Pass,
            "DPO desemnat.",
            "Asigurați independența DPO și raportarea directă " +
            "către conducere (Art. 38)."));
    }

    private void CheckDpia()
    {
        var reasons = new List<string>();
        // Cazurile explicite din art. 35(3)
        if (_profile.AutomatedDecisionsWithLegalEffect)
            reasons.Add("art. 35(3)(a): decizii automate cu efecte juridice");
        if (_profile.ProcessesSensitiveData && _profile.LargeScaleProcessing)
            reasons.Add("art. 35(3)(b): date sensibile pe scară largă");
        if (_profile.MonitorsPublicAreas && _profile.LargeScaleProcessing)
            reasons.Add("art. 35(3)(c): zone publice pe scară largă");
        // Ghidurile WP248 (Grupul de lucru Art. 29, preluate de EDPB):
        // DPIA dacă sunt îndeplinite >= 2 criterii
        int edpbCriteria = new[] {
            _profile.ProfilesUsers, _profile.SystematicMonitoring,
            _profile.ProcessesSensitiveData, _profile.LargeScaleProcessing
        }.Count(c => c);
        if (reasons.Count == 0 && edpbCriteria >= 2)
            reasons.Add($"{edpbCriteria} criterii din ghidurile WP248 îndeplinite");

        if (reasons.Count > 0 && !_profile.HasCompletedDpia)
        {
            _results.Add(new ComplianceCheck(
                "DPIA", "Evaluarea impactului",
                ComplianceStatus.Warning,
                $"DPIA necesară, neefectuată: {string.Join("; ", reasons)}.",
                "Efectuați DPIA înainte de a începe prelucrarea " +
                "(art. 35); dacă riscul rămâne ridicat, art. 36."));
            return;
        }

        if (reasons.Count > 0)
        {
            _results.Add(new ComplianceCheck(
                "DPIA", "Evaluarea impactului",
                ComplianceStatus.Pass,
                "DPIA necesară și efectuată.",
                "Revizuiți DPIA când prelucrarea se schimbă."));
            return;
        }

        _results.Add(new ComplianceCheck(
            "DPIA", "Evaluarea impactului",
            ComplianceStatus.Pass,
            "DPIA nu este obligatorie pentru profilul actual.",
            "Reevaluați dacă prelucrarea se modifică semnificativ."));
    }


    // Împarte un text lung pe mai multe rânduri (lățime maximă dată)
    private static IEnumerable<string> Wrap(string text, int width)
    {
        var line = "";
        foreach (var word in text.Split(' '))
        {
            if (line.Length > 0 && line.Length + 1 + word.Length > width)
            {
                yield return line;
                line = word;
            }
            else line = line.Length == 0 ? word : line + " " + word;
        }
        if (line.Length > 0) yield return line;
    }

    public void PrintScorecard()
    {
        var line = new string('═', 60);
        Console.WriteLine($"\n{line}");
        Console.WriteLine("  Verificare de conformitate GDPR");
        Console.WriteLine($"  {_profile.Name}");
        Console.WriteLine($"{line}\n");

        int pass = 0, warn = 0, fail = 0;

        foreach (var check in _results)
        {
            var icon = check.Status switch
            {
                ComplianceStatus.Pass => "[PASS]   ",
                ComplianceStatus.Warning => "[WARNING]",
                ComplianceStatus.Fail => "[FAIL]   ",
                _ => "[?]      "
            };

            Console.WriteLine($"  {icon} {check.Area}: {check.Description}");
            foreach (var l in Wrap(check.Details, 56))
                Console.WriteLine($"            {l}");
            if (check.Status != ComplianceStatus.Pass)
                foreach (var (l, i) in Wrap("-> " + check.Recommendation, 56)
                             .Select((l, i) => (l, i)))
                    Console.WriteLine($"            {(i == 0 ? "" : "   ")}{l}");
            Console.WriteLine();

            switch (check.Status)
            {
                case ComplianceStatus.Pass: pass++; break;
                case ComplianceStatus.Warning: warn++; break;
                case ComplianceStatus.Fail: fail++; break;
            }
        }

        Console.WriteLine(new string('─', 60));
        Console.WriteLine(
            $"  Total: {_results.Count} verificări | " +
            $"{pass} PASS | {warn} WARNING | {fail} FAIL");

        double score = (pass * 100.0 + warn * 50.0) / _results.Count;
        Console.WriteLine($"  Scor de conformitate: {score:F0}%");

        string verdict = score switch
        {
            >= 90 => "Conformitate ridicată",
            >= 70 => "Conformitate parțială: acțiuni corective necesare",
            >= 50 => "Conformitate scăzută: riscuri semnificative",
            _ => "Neconform: acțiuni imediate necesare"
        };
        Console.WriteLine($"  Verdict: {verdict}");
        Console.WriteLine(line);
    }
}

public class Program
{
    public static void Main()
    {
        // Profil aplicație exemplu: platformă e-commerce
        var profile = new ApplicationProfile(
            Name: "ShopSecure SRL — Platformă e-commerce",
            HasConsentMechanism: true,
            ConsentIsGranular: true,
            ConsentIsWithdrawable: false,  // Deficiență: retragere dificilă
            PreTickedBoxes: false,
            DataFieldsCollected: [
                "nume", "email", "telefon", "adresă",
                "data nașterii", "gen", "istoric comenzi",
                "adresă IP", "cookies preferințe"
            ],
            DataFieldsRequired: [
                "nume", "email", "telefon", "adresă",
                "istoric comenzi"
            ],
            EncryptsDataAtRest: true,
            EncryptsDataInTransit: true,
            EncryptionAlgorithm: "AES-256 + TLS 1.3",
            HasRetentionPolicy: true,
            RetentionDays: 365,
            AutoDeletesExpiredData: false,  // Deficiență: fără ștergere automată
            HasBreachNotificationProcedure: true,
            BreachNotificationHours: 48,
            HasDpo: false,  // Deficiență: fără DPO
            IsPublicAuthority: false,
            SystematicMonitoring: true, // urmărirea comportamentului online
            ProcessesSensitiveData: false,
            ProfilesUsers: true,  // profilare pentru recomandări
            AutomatedDecisionsWithLegalEffect: false,
            LargeScaleProcessing: true,
            MonitorsPublicAreas: false,
            HasCompletedDpia: false,
            EstimatedDataSubjects: 50_000
        );

        var checker = new GdprComplianceChecker(profile);
        checker.Evaluate();
        checker.PrintScorecard();
    }
}
