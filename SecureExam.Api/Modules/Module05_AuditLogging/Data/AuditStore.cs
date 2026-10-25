using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureExam.Api.Models;

namespace SecureExam.Api.Data;

internal sealed class AuditStore
{
    private const string GenesisHash = "GENESIS";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;
    private readonly SemaphoreSlim _appendLock = new(1, 1);

    public AuditStore(IConfiguration configuration)
    {
        var dataDirectory = configuration["SECURE_EXAM_DATA_DIR"];
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            dataDirectory = Path.Combine(AppContext.BaseDirectory, "data");
        }

        Directory.CreateDirectory(dataDirectory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(dataDirectory, "secure-exam-auth.db"),
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "CREATE TABLE IF NOT EXISTS audit_events (" +
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE," +
            "server_timestamp TEXT NOT NULL,event_type TEXT NOT NULL,user_id TEXT NULL,workstation_id TEXT NULL," +
            "resource_type TEXT NULL,resource_id TEXT NULL,outcome TEXT NOT NULL,details TEXT NOT NULL," +
            "previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);" +
            "CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(server_timestamp DESC);" +
            "CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events " +
            "BEGIN SELECT RAISE(ABORT,'audit events are append-only'); END;" +
            "CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events " +
            "BEGIN SELECT RAISE(ABORT,'audit events are append-only'); END;";
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task AppendAsync(
        string eventType,
        string? userId,
        string? workstationId,
        string? resourceType,
        string? resourceId,
        string outcome,
        string details,
        CancellationToken cancellationToken)
    {
        await _appendLock.WaitAsync(cancellationToken);
        try
        {
            await using var connection = await OpenAsync(cancellationToken);
            await using var transaction = connection.BeginTransaction();
            var last = connection.CreateCommand();
            last.Transaction = transaction;
            last.CommandText = "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1;";
            await using var reader = await last.ExecuteReaderAsync(cancellationToken);
            var sequence = 1L;
            var previousHash = GenesisHash;
            if (await reader.ReadAsync(cancellationToken))
            {
                sequence = reader.GetInt64(0) + 1;
                previousHash = reader.GetString(1);
            }

            await reader.DisposeAsync();
            var timestamp = DateTimeOffset.UtcNow;
            var eventId = Guid.NewGuid().ToString("N");
            var canonical = new AuditEvent(
                sequence,
                eventId,
                timestamp,
                Limit(eventType, 80),
                LimitNullable(userId, 100),
                LimitNullable(workstationId, 100),
                LimitNullable(resourceType, 80),
                LimitNullable(resourceId, 200),
                Limit(outcome, 40),
                Limit(details, 1000),
                previousHash,
                string.Empty);
            var eventHash = ComputeHash(canonical);
            var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText =
                "INSERT INTO audit_events(sequence,event_id,server_timestamp,event_type,user_id,workstation_id," +
                "resource_type,resource_id,outcome,details,previous_hash,event_hash) " +
                "VALUES($sequence,$id,$timestamp,$type,$user,$workstation,$resourceType,$resourceId,$outcome,$details,$previous,$hash);";
            insert.Parameters.AddWithValue("$sequence", sequence);
            insert.Parameters.AddWithValue("$id", eventId);
            insert.Parameters.AddWithValue("$timestamp", timestamp.ToString("O"));
            insert.Parameters.AddWithValue("$type", canonical.EventType);
            insert.Parameters.AddWithValue("$user", (object?)canonical.UserId ?? DBNull.Value);
            insert.Parameters.AddWithValue("$workstation", (object?)canonical.WorkstationId ?? DBNull.Value);
            insert.Parameters.AddWithValue("$resourceType", (object?)canonical.ResourceType ?? DBNull.Value);
            insert.Parameters.AddWithValue("$resourceId", (object?)canonical.ResourceId ?? DBNull.Value);
            insert.Parameters.AddWithValue("$outcome", canonical.Outcome);
            insert.Parameters.AddWithValue("$details", canonical.Details);
            insert.Parameters.AddWithValue("$previous", previousHash);
            insert.Parameters.AddWithValue("$hash", eventHash);
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            _appendLock.Release();
        }
    }

    public async Task<IReadOnlyList<AuditEvent>> ListAsync(int limit, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT sequence,event_id,server_timestamp,event_type,user_id,workstation_id,resource_type," +
            "resource_id,outcome,details,previous_hash,event_hash FROM audit_events " +
            "ORDER BY sequence DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        var events = new List<AuditEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(ReadEvent(reader));
        }

        return events;
    }

    public async Task<AuditVerificationResult> VerifyAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT sequence,event_id,server_timestamp,event_type,user_id,workstation_id,resource_type," +
            "resource_id,outcome,details,previous_hash,event_hash FROM audit_events ORDER BY sequence;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var expectedSequence = 1L;
        var expectedPreviousHash = GenesisHash;
        var checkedEvents = 0L;
        while (await reader.ReadAsync(cancellationToken))
        {
            var auditEvent = ReadEvent(reader);
            checkedEvents++;
            if (auditEvent.Sequence != expectedSequence ||
                !string.Equals(auditEvent.PreviousHash, expectedPreviousHash, StringComparison.Ordinal) ||
                !string.Equals(auditEvent.EventHash, ComputeHash(auditEvent), StringComparison.Ordinal))
            {
                return new AuditVerificationResult(
                    false,
                    checkedEvents,
                    auditEvent.Sequence,
                    "The audit chain contains a modified, missing, or reordered event.");
            }

            expectedSequence++;
            expectedPreviousHash = auditEvent.EventHash;
        }

        return new AuditVerificationResult(true, checkedEvents, null, "Audit hash chain is valid.");
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static AuditEvent ReadEvent(SqliteDataReader reader) =>
        new(
            reader.GetInt64(0),
            reader.GetString(1),
            DateTimeOffset.Parse(reader.GetString(2)),
            reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetString(6),
            reader.IsDBNull(7) ? null : reader.GetString(7),
            reader.GetString(8),
            reader.GetString(9),
            reader.GetString(10),
            reader.GetString(11));

    private static string ComputeHash(AuditEvent auditEvent)
    {
        var canonical = JsonSerializer.SerializeToUtf8Bytes(new
        {
            auditEvent.Sequence,
            auditEvent.EventId,
            ServerTimestamp = auditEvent.ServerTimestamp.ToUniversalTime().ToString("O"),
            auditEvent.EventType,
            auditEvent.UserId,
            auditEvent.WorkstationId,
            auditEvent.ResourceType,
            auditEvent.ResourceId,
            auditEvent.Outcome,
            auditEvent.Details,
            auditEvent.PreviousHash
        }, JsonOptions);
        return Convert.ToHexString(SHA256.HashData(canonical));
    }

    private static string Limit(string value, int maximumLength) =>
        value.Length <= maximumLength ? value : value[..maximumLength];

    private static string? LimitNullable(string? value, int maximumLength) =>
        value is null ? null : Limit(value, maximumLength);
}
