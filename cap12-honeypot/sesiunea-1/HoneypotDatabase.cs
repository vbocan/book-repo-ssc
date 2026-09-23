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
        // WAL permite scrieri concurente fără blocaje lungi
        command.CommandText = @"
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS ConnectionLog (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Timestamp TEXT NOT NULL,
                SourceIP TEXT NOT NULL,
                SourcePort INTEGER NOT NULL,
                DestinationPort INTEGER NOT NULL,
                InitialData TEXT
            );";
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
}
