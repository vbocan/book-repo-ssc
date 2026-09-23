using Microsoft.Data.Sqlite;

namespace Honeypot;

public class ConnectionRecord
{
    public DateTime Timestamp { get; set; }
    public string SourceIP { get; set; } = "";
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public string InitialData { get; set; } = "";
}

public record BasicStats(long TotalConnections, long ConnectionsLastHour,
    long ConnectionsLast24h, double DatabaseSizeMB);

public class HoneypotDatabase
{
    private readonly string _connectionString;

    public HoneypotDatabase(string dbPath = "honeypot.db")
    {
        _connectionString = $"Data Source={dbPath}";
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        var command = connection.CreateCommand();
        // Fiecare instrucțiune se termină cu „;” (SQLite le execută pe rând)
        command.CommandText = @"
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS ConnectionLog (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Timestamp TEXT NOT NULL,
                SourceIP TEXT NOT NULL,
                SourcePort INTEGER NOT NULL,
                DestinationPort INTEGER NOT NULL,
                InitialData TEXT
            );

            CREATE TABLE IF NOT EXISTS InteractionLog (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                ConnectionId INTEGER NOT NULL,
                Timestamp TEXT NOT NULL,
                Direction TEXT NOT NULL,
                Data TEXT NOT NULL,
                FOREIGN KEY (ConnectionId) REFERENCES ConnectionLog(Id)
            );

            CREATE TABLE IF NOT EXISTS CredentialLog (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                ConnectionId INTEGER NOT NULL,
                Timestamp TEXT NOT NULL,
                Service TEXT NOT NULL,
                Username TEXT NOT NULL,
                Password TEXT NOT NULL,
                FOREIGN KEY (ConnectionId) REFERENCES ConnectionLog(Id)
            );

            CREATE INDEX IF NOT EXISTS IX_Interaction_Connection
                ON InteractionLog(ConnectionId);
            CREATE INDEX IF NOT EXISTS IX_Credential_Connection
                ON CredentialLog(ConnectionId);";
        command.ExecuteNonQuery();
    }

    public long LogConnection(ConnectionRecord record)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO ConnectionLog
                (Timestamp, SourceIP, SourcePort, DestinationPort, InitialData)
            VALUES (@ts, @sip, @sport, @dport, @data);
            SELECT last_insert_rowid();";
        command.Parameters.AddWithValue("@ts", record.Timestamp.ToString("o"));
        command.Parameters.AddWithValue("@sip", record.SourceIP);
        command.Parameters.AddWithValue("@sport", record.SourcePort);
        command.Parameters.AddWithValue("@dport", record.DestinationPort);
        command.Parameters.AddWithValue("@data", record.InitialData);
        return (long)command.ExecuteScalar()!;
    }

    public void LogInteraction(long connectionId, string direction, string data)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO InteractionLog (ConnectionId, Timestamp, Direction, Data)
            VALUES (@cid, @ts, @dir, @data);";
        command.Parameters.AddWithValue("@cid", connectionId);
        command.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
        command.Parameters.AddWithValue("@dir", direction);
        command.Parameters.AddWithValue("@data", data);
        command.ExecuteNonQuery();
    }

    public void LogCredential(long connectionId, string service,
        string username, string password)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO CredentialLog
                (ConnectionId, Timestamp, Service, Username, Password)
            VALUES (@cid, @ts, @svc, @user, @pass);";
        command.Parameters.AddWithValue("@cid", connectionId);
        command.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
        command.Parameters.AddWithValue("@svc", service);
        command.Parameters.AddWithValue("@user", username);
        command.Parameters.AddWithValue("@pass", password);
        command.ExecuteNonQuery();
    }

    public BasicStats GetBasicStats()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        var command = connection.CreateCommand();
        // Timestamp-urile sunt ISO 8601 UTC, deci se pot compara ca text
        command.CommandText = @"
            SELECT COUNT(*),
                   COALESCE(SUM(Timestamp >= @hour), 0),
                   COALESCE(SUM(Timestamp >= @day), 0)
            FROM ConnectionLog;";
        var now = DateTime.UtcNow;
        command.Parameters.AddWithValue("@hour", now.AddHours(-1).ToString("o"));
        command.Parameters.AddWithValue("@day", now.AddHours(-24).ToString("o"));
        using var reader = command.ExecuteReader();
        reader.Read();
        // Mărimea include jurnalul WAL (honeypot.db-wal), unde ajung scrierile recente
        var dbPath = new SqliteConnectionStringBuilder(_connectionString).DataSource;
        var files = new[] { dbPath, dbPath + "-wal" }.Where(File.Exists);
        var sizeMB = files.Sum(f => new FileInfo(f).Length) / 1048576.0;
        return new BasicStats(reader.GetInt64(0), reader.GetInt64(1),
            reader.GetInt64(2), sizeMB);
    }

    // Copie consistentă a bazei de date, chiar în timp ce honeypot-ul scrie în ea
    public void BackupTo(string destinationPath)
    {
        if (File.Exists(destinationPath))
            File.Delete(destinationPath);
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = "VACUUM INTO @dest;";
        command.Parameters.AddWithValue("@dest", destinationPath);
        command.ExecuteNonQuery();
    }
}
