using Microsoft.Data.Sqlite;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers;

namespace Honeypot;

// O instanță = o „sesiune”: toate conexiunile unui IP într-o fereastră de o oră
public class AttackData
{
    public float ConnectionsPerMinute { get; set; }
    public float UniquePortsAccessed { get; set; }
    public float AvgBytesReceived { get; set; }
    public float CredentialAttempts { get; set; }
    public float SessionDurationSeconds { get; set; }
    public float TimeOfDayHour { get; set; }
    public string Label { get; set; } = "";

    // Numărătorile au distribuții foarte asimetrice (0, 3, 15, 300...):
    // log(1 + x) le aduce pe o scară pe care un model liniar le poate separa
    public float LogConnectionsPerMinute => MathF.Log(1 + ConnectionsPerMinute);
    public float LogBytesReceived => MathF.Log(1 + AvgBytesReceived);
    public float LogCredentialAttempts => MathF.Log(1 + CredentialAttempts);
    public float LogDuration => MathF.Log(1 + SessionDurationSeconds);
}

public class AttackPrediction
{
    [ColumnName("PredictedLabel")] public string PredictedLabel { get; set; } = "";
    public float[] Score { get; set; } = [];
}

public class AttackClassifier
{
    private readonly MLContext _mlContext = new(seed: 42);
    private PredictionEngine<AttackData, AttackPrediction>? _predictionEngine;

    // Date sintetice, cu intervale alese ilustrativ pentru un honeypot cu 5 porturi.
    // În producție, un analist etichetează manual un eșantion de sesiuni reale.
    public List<AttackData> GenerateTrainingData()
    {
        var random = new Random(42);
        float R(double min, double max) =>
            (float)(min + random.NextDouble() * (max - min));
        var data = new List<AttackData>();

        for (int i = 0; i < 100; i++)   // FTP/Telnet/HTTP: multe parole, un serviciu
            data.Add(new AttackData
            {
                ConnectionsPerMinute = R(0.5, 30), UniquePortsAccessed = 1,
                AvgBytesReceived = R(20, 600),
                CredentialAttempts = MathF.Round(R(3, 100)),
                SessionDurationSeconds = R(5, 3600), TimeOfDayHour = R(0, 24),
                Label = "BruteForce"
            });

        for (int i = 0; i < 100; i++)   // SSH: parolele nu se văd, doar rata conexiunilor
            data.Add(new AttackData
            {
                ConnectionsPerMinute = R(8, 60), UniquePortsAccessed = 1,
                AvgBytesReceived = R(100, 2000), CredentialAttempts = 0,
                SessionDurationSeconds = R(0, 3600), TimeOfDayHour = R(0, 24),
                Label = "BruteForce"
            });

        for (int i = 0; i < 200; i++)   // 3–5 porturi în câteva secunde, fără date
            data.Add(new AttackData
            {
                ConnectionsPerMinute = R(3, 10),
                UniquePortsAccessed = MathF.Round(R(3, 5)),
                AvgBytesReceived = R(0, 120), CredentialAttempts = 0,
                SessionDurationSeconds = R(0, 20), TimeOfDayHour = R(0, 24),
                Label = "PortScan"
            });

        for (int i = 0; i < 200; i++)   // citește bannere, câteva cereri, rar o parolă
            data.Add(new AttackData
            {
                ConnectionsPerMinute = R(0.2, 5),
                UniquePortsAccessed = MathF.Round(R(1, 3)),
                AvgBytesReceived = R(20, 800), CredentialAttempts = MathF.Round(R(0, 2)),
                SessionDurationSeconds = R(0, 900), TimeOfDayHour = R(0, 24),
                Label = "Reconnaissance"
            });

        for (int i = 0; i < 200; i++)   // Shodan, Censys: o cerere scurtă și pleacă
            data.Add(new AttackData
            {
                ConnectionsPerMinute = R(0.1, 2),
                UniquePortsAccessed = MathF.Round(R(1, 2)),
                AvgBytesReceived = R(0, 150), CredentialAttempts = 0,
                SessionDurationSeconds = R(0, 5), TimeOfDayHour = R(0, 24),
                Label = "ResearchScanner"
            });

        return data;
    }

    public List<(string IP, AttackData Features)> ExtractFeaturesFromDatabase(
        string dbPath)
    {
        var sessions = new List<(string, AttackData)>();
        using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly");
        conn.Open();
        using var cmd = conn.CreateCommand();
        // Pasul 1 (CTE): o linie per conexiune, cu octeții primiți, numărul de
        // credențiale și momentul ultimei interacțiuni, calculate prin subinterogări.
        // Pasul 2: agregare pe IP și fereastră de o oră. Fără JOIN direct, deci
        // COUNT(*) numără conexiuni, nu rânduri din InteractionLog.
        cmd.CommandText = @"
            WITH conn AS (
                SELECT c.Id, c.SourceIP, c.DestinationPort, c.Timestamp,
                       strftime('%Y-%m-%d %H', c.Timestamp) AS window,
                       COALESCE((SELECT SUM(LENGTH(i.Data)) FROM InteractionLog i
                                 WHERE i.ConnectionId = c.Id AND i.Direction = 'RECV'), 0)
                           AS bytes_in,
                       (SELECT COUNT(*) FROM CredentialLog k
                        WHERE k.ConnectionId = c.Id) AS creds,
                       COALESCE((SELECT MAX(i.Timestamp) FROM InteractionLog i
                                 WHERE i.ConnectionId = c.Id), c.Timestamp) AS last_ts
                FROM ConnectionLog c
            )
            SELECT SourceIP,
                   COUNT(*) * 1.0 / MAX(1.0,
                       (julianday(MAX(Timestamp)) - julianday(MIN(Timestamp))) * 1440),
                   COUNT(DISTINCT DestinationPort),
                   AVG(bytes_in),
                   SUM(creds),
                   (julianday(MAX(last_ts)) - julianday(MIN(Timestamp))) * 86400,
                   CAST(strftime('%H', MIN(Timestamp)) AS REAL)
            FROM conn
            GROUP BY SourceIP, window
            ORDER BY MIN(Timestamp)";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            sessions.Add((reader.GetString(0), new AttackData
            {
                ConnectionsPerMinute = reader.GetFloat(1),
                UniquePortsAccessed = reader.GetFloat(2),
                AvgBytesReceived = reader.GetFloat(3),
                CredentialAttempts = reader.GetFloat(4),
                SessionDurationSeconds = reader.GetFloat(5),
                TimeOfDayHour = reader.GetFloat(6)
            }));
        return sessions;
    }

    public void Train()
    {
        var dataView = _mlContext.Data.LoadFromEnumerable(GenerateTrainingData());
        var split = _mlContext.Data.TrainTestSplit(dataView, testFraction: 0.2);

        var pipeline = _mlContext.Transforms.Conversion.MapValueToKey("Label")
            .Append(_mlContext.Transforms.Concatenate("Features",
                nameof(AttackData.LogConnectionsPerMinute),
                nameof(AttackData.UniquePortsAccessed),
                nameof(AttackData.LogBytesReceived),
                nameof(AttackData.LogCredentialAttempts),
                nameof(AttackData.LogDuration),
                nameof(AttackData.TimeOfDayHour)))
            // SDCA cere caracteristici pe scale comparabile: le aducem în [0, 1]
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            // Un singur fir de execuție: rezultate identice la fiecare rulare
            .Append(_mlContext.MulticlassClassification.Trainers.SdcaMaximumEntropy(
                new SdcaMaximumEntropyMulticlassTrainer.Options { NumberOfThreads = 1 }))
            .Append(_mlContext.Transforms.Conversion.MapKeyToValue("PredictedLabel"));

        Console.WriteLine("Training attack classifier...");
        var model = pipeline.Fit(split.TrainSet);

        var predictions = model.Transform(split.TestSet);
        var metrics = _mlContext.MulticlassClassification.Evaluate(predictions);
        var testCount = metrics.ConfusionMatrix.Counts.Sum(row => row.Sum());
        Console.WriteLine($"\nTest set: {testCount:F0} sessions");
        Console.WriteLine($"  Macro accuracy: {metrics.MacroAccuracy:P2}");
        Console.WriteLine($"  Micro accuracy: {metrics.MicroAccuracy:P2}");
        Console.WriteLine($"  Log loss:       {metrics.LogLoss:F4}");

        // Numele claselor, în ordinea cheilor create de MapValueToKey
        VBuffer<ReadOnlyMemory<char>> keys = default;
        predictions.Schema["Label"].GetKeyValues(ref keys);
        var classes = keys.DenseValues().Select(k => k.ToString()).ToArray();

        var cm = metrics.ConfusionMatrix;
        Console.WriteLine($"\n  {"Class",-16} {"Precision",9} {"Recall",7} {"F1",6}");
        for (int i = 0; i < classes.Length; i++)
        {
            var p = cm.PerClassPrecision[i];
            var r = cm.PerClassRecall[i];
            var f1 = p + r > 0 ? 2 * p * r / (p + r) : 0;
            Console.WriteLine($"  {classes[i],-16} {p,9:F3} {r,7:F3} {f1,6:F3}");
        }

        Console.WriteLine("\n  Confusion matrix (rows = actual, columns = predicted):");
        Console.WriteLine("  " + new string(' ', 16) +
            string.Concat(classes.Select(c => $"{c[..5],7}")));
        for (int i = 0; i < classes.Length; i++)
            Console.WriteLine($"  {classes[i],-16}" +
                string.Concat(cm.Counts[i].Select(v => $"{v,7:F0}")));

        _predictionEngine = _mlContext.Model
            .CreatePredictionEngine<AttackData, AttackPrediction>(model);
    }

    public void ClassifyHoneypotData(string dbPath)
    {
        if (_predictionEngine == null)
            throw new InvalidOperationException("Model not trained. Call Train() first.");

        var sessions = ExtractFeaturesFromDatabase(dbPath);
        Console.WriteLine($"\nClassifying {sessions.Count} sessions (IP x hour):\n");
        Console.WriteLine($"  {"Source IP",-15} {"Conn/min",8} {"Ports",5} {"Bytes",6} " +
                          $"{"Creds",5} {"Dur(s)",7}  Prediction");

        var classCounts = new Dictionary<string, int>();
        foreach (var (ip, session) in sessions)
        {
            var label = _predictionEngine.Predict(session).PredictedLabel;
            classCounts[label] = classCounts.GetValueOrDefault(label) + 1;
            Console.WriteLine(
                $"  {ip,-15} {session.ConnectionsPerMinute,8:F1} " +
                $"{session.UniquePortsAccessed,5:F0} {session.AvgBytesReceived,6:F0} " +
                $"{session.CredentialAttempts,5:F0} " +
                $"{session.SessionDurationSeconds,7:F1}  {label}");
        }

        Console.WriteLine("\nSummary:");
        foreach (var (label, count) in classCounts.OrderByDescending(kv => kv.Value))
            Console.WriteLine($"  {label,-16} {count,3} sessions");
    }
}
