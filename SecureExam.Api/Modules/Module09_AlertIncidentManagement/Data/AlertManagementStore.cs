using Microsoft.Data.Sqlite;
using SecureExam.Api.Models;

namespace SecureExam.Api.Data;

internal sealed class AlertManagementStore
{
    private static readonly TimeSpan SignalWindow = TimeSpan.FromMinutes(15);
    private const int FailedLoginThreshold = 5;
    private const int SuspiciousExportThreshold = 3;
    private const int MaxSignals = 1000;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private bool _initialized;

    public AlertManagementStore(IConfiguration configuration)
    {
        var dataDirectory = configuration["SECURE_EXAM_DATA_DIR"];
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            dataDirectory = Path.Combine(AppContext.BaseDirectory, "data");
        }

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(dataDirectory, "secure-exam-auth.db"),
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        if (_initialized)
        {
            return;
        }

        await _initializeLock.WaitAsync(cancellationToken);
        try
        {
            if (_initialized)
            {
                return;
            }

            await using var connection = await OpenAsync(cancellationToken);
            var command = connection.CreateCommand();
            command.CommandText =
                "CREATE TABLE IF NOT EXISTS security_alerts(" +
                "alert_id TEXT PRIMARY KEY,alert_type TEXT NOT NULL,severity TEXT NOT NULL,summary TEXT NOT NULL," +
                "details TEXT NOT NULL,actor_user_id TEXT NULL,workstation_id TEXT NULL,resource_type TEXT NULL," +
                "resource_id TEXT NULL,created_at TEXT NOT NULL,dedupe_key TEXT NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_security_alerts_created ON security_alerts(created_at DESC);" +
                "CREATE INDEX IF NOT EXISTS idx_security_alerts_dedupe ON security_alerts(dedupe_key,created_at DESC);" +
                "CREATE TABLE IF NOT EXISTS alert_signal_events(" +
                "signal_id TEXT PRIMARY KEY,signal_type TEXT NOT NULL,signal_key TEXT NOT NULL,actor_user_id TEXT NULL," +
                "workstation_id TEXT NULL,resource_id TEXT NULL,occurred_at TEXT NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_alert_signals_window ON alert_signal_events(signal_type,signal_key,occurred_at DESC);" +
                "CREATE TABLE IF NOT EXISTS security_alert_actions(" +
                "action_id TEXT PRIMARY KEY,alert_id TEXT NOT NULL,action TEXT NOT NULL,actor_user_id TEXT NOT NULL," +
                "actor_name TEXT NOT NULL,note TEXT NULL,occurred_at TEXT NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_alert_actions_alert ON security_alert_actions(alert_id,occurred_at DESC);" +
                "CREATE TABLE IF NOT EXISTS alert_cases(" +
                "case_id TEXT PRIMARY KEY,alert_id TEXT NOT NULL,summary TEXT NOT NULL,created_by TEXT NOT NULL," +
                "created_at TEXT NOT NULL);" +
                "CREATE TRIGGER IF NOT EXISTS security_alerts_no_update BEFORE UPDATE ON security_alerts " +
                "BEGIN SELECT RAISE(ABORT,'security alerts are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS security_alerts_no_delete BEFORE DELETE ON security_alerts " +
                "BEGIN SELECT RAISE(ABORT,'security alerts are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS security_alert_actions_no_update BEFORE UPDATE ON security_alert_actions " +
                "BEGIN SELECT RAISE(ABORT,'alert actions are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS security_alert_actions_no_delete BEFORE DELETE ON security_alert_actions " +
                "BEGIN SELECT RAISE(ABORT,'alert actions are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS alert_cases_no_update BEFORE UPDATE ON alert_cases " +
                "BEGIN SELECT RAISE(ABORT,'alert cases are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS alert_cases_no_delete BEFORE DELETE ON alert_cases " +
                "BEGIN SELECT RAISE(ABORT,'alert cases are append-only'); END;";
            await command.ExecuteNonQueryAsync(cancellationToken);
            _initialized = true;
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    public async Task ObserveRequestAsync(
        string path,
        int statusCode,
        string? actorUserId,
        string? workstationId,
        string sourceAddress,
        string? resourceId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        var isLoginAttempt = path is "/api/auth/login" or "/api/auth/mfa/setup" or "/api/auth/mfa/verify";
        var isExport = path.EndsWith("/export", StringComparison.Ordinal) ||
                       path.EndsWith("/watermarked-copy", StringComparison.Ordinal);

        if (isLoginAttempt && statusCode is >= 400)
        {
            await RecordSignalAsync(
                "failed_login",
                sourceAddress,
                actorUserId,
                workstationId,
                null,
                FailedLoginThreshold,
                now,
                "repeated_failed_login",
                "high",
                "Repeated sign-in or MFA failures",
                $"At least {FailedLoginThreshold} sign-in or MFA attempts from API connection peer {sourceAddress} were denied within 15 minutes. The address is not a trusted identity.",
                cancellationToken);
        }

        if (!isLoginAttempt && (statusCode is 401 or 403))
        {
            var dedupe = $"{sourceAddress}|{path.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "api"}";
            await CreateAlertUnlessRecentAsync(
                "unauthorized_access",
                "high",
                "Unauthorized access attempt",
                $"A request from API connection peer {sourceAddress} to {path} was denied with HTTP {statusCode}.",
                actorUserId,
                workstationId,
                "api_resource",
                resourceId ?? path,
                dedupe,
                now,
                cancellationToken);
        }

        if (isExport && statusCode is >= 400)
        {
            await CreateAlertUnlessRecentAsync(
                "denied_export",
                "high",
                "Export was denied",
                $"A controlled export request from API connection peer {sourceAddress} to {path} was denied with HTTP {statusCode}.",
                actorUserId,
                workstationId,
                "paper",
                resourceId,
                $"denied-export:{actorUserId ?? sourceAddress}:{resourceId ?? path}",
                now,
                cancellationToken);
        }
        else if (isExport && statusCode is >= 200 and < 300 && actorUserId is not null && resourceId is not null)
        {
            await RecordSignalAsync(
                "successful_export",
                $"{actorUserId}:{resourceId}",
                actorUserId,
                workstationId,
                resourceId,
                SuspiciousExportThreshold,
                now,
                "suspicious_export_volume",
                "medium",
                "High volume of exports",
                $"At least {SuspiciousExportThreshold} successful paper exports by the same account for this paper occurred within 15 minutes.",
                cancellationToken);
        }
    }

    public async Task RecordUnregisteredDeviceAsync(
        string userId,
        string deviceId,
        string deviceName,
        CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        await CreateAlertUnlessRecentAsync(
            "unregistered_device",
            "high",
            "Unregistered workstation sign-in",
            $"Account {userId} completed MFA on a workstation awaiting administrator approval ({Limit(deviceName, 100)}).",
            userId,
            deviceId,
            "device",
            deviceId,
            $"unregistered-device:{userId}:{deviceId}",
            DateTimeOffset.UtcNow,
            cancellationToken);
    }

    public async Task<IReadOnlyList<SecurityAlert>> ListAsync(
        int limit,
        string? status,
        CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = AlertSelect +
            " WHERE ($status IS NULL OR COALESCE((SELECT action FROM security_alert_actions x " +
            "WHERE x.alert_id=a.alert_id AND x.action IN ('reviewed','resolved') " +
            "ORDER BY x.occurred_at DESC LIMIT 1),'open')=$status) " +
            "ORDER BY a.created_at DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 500));
        command.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
        var alerts = new List<SecurityAlert>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            alerts.Add(ReadAlert(reader));
        }

        return alerts;
    }

    public async Task<IReadOnlyList<AlertCase>> ListCasesAsync(CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT c.case_id,c.alert_id,c.summary,c.created_by,COALESCE(u.display_name,'Unknown user'),c.created_at," +
            "CASE WHEN EXISTS(SELECT 1 FROM security_alert_actions a WHERE a.alert_id=c.alert_id AND a.action='resolved') " +
            "THEN 'resolved' ELSE 'open' END FROM alert_cases c LEFT JOIN users u ON u.user_id=c.created_by " +
            "ORDER BY c.created_at DESC LIMIT 500;";
        var cases = new List<AlertCase>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            cases.Add(new AlertCase(
                reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), DateTimeOffset.Parse(reader.GetString(5)), reader.GetString(6)));
        }

        return cases;
    }

    public async Task<SecurityAlert?> GetAsync(string alertId, CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = AlertSelect + " WHERE a.alert_id=$id;";
        command.Parameters.AddWithValue("$id", alertId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadAlert(reader) : null;
    }

    public async Task<AlertCase?> CreateCaseAsync(
        string alertId,
        CreateAlertCaseRequest request,
        string actorUserId,
        string actorName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var summary = request.Summary?.Trim();
        if (string.IsNullOrWhiteSpace(summary) || summary.Length > 1000)
        {
            throw new ArgumentException("Enter an incident case summary of up to 1,000 characters.");
        }

        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var alertCommand = connection.CreateCommand();
        alertCommand.Transaction = transaction;
        alertCommand.CommandText =
            "SELECT alert_type,summary FROM security_alerts WHERE alert_id=$id;";
        alertCommand.Parameters.AddWithValue("$id", alertId);
        await using var reader = await alertCommand.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var alertType = reader.GetString(0);
        var alertSummary = reader.GetString(1);
        await reader.DisposeAsync();
        var currentStatus = await GetStatusAsync(connection, transaction, alertId, cancellationToken);
        if (currentStatus == "resolved")
        {
            throw new InvalidOperationException("A resolved alert cannot be opened as a new incident case.");
        }

        var caseId = Guid.NewGuid().ToString("N");
        var createdAt = now.ToUniversalTime();
        var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            "INSERT INTO alert_cases(case_id,alert_id,summary,created_by,created_at) " +
            "VALUES($case,$alert,$summary,$user,$created);";
        insert.Parameters.AddWithValue("$case", caseId);
        insert.Parameters.AddWithValue("$alert", alertId);
        insert.Parameters.AddWithValue("$summary", summary);
        insert.Parameters.AddWithValue("$user", actorUserId);
        insert.Parameters.AddWithValue("$created", createdAt.ToString("O"));
        await insert.ExecuteNonQueryAsync(cancellationToken);

        await InsertActionAsync(
            connection, transaction, alertId, "case_created", actorUserId, actorName,
            $"Case {caseId}: {summary} (alert: {alertType} — {alertSummary})", createdAt, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new AlertCase(caseId, alertId, summary, actorUserId, actorName, createdAt, "open");
    }

    public async Task<SecurityAlert?> AddActionAsync(
        string alertId,
        string action,
        string actorUserId,
        string actorName,
        string? note,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (action is not ("reviewed" or "resolved"))
        {
            throw new ArgumentException("Unsupported alert action.");
        }

        if (note?.Length > 1000 || (action == "resolved" && string.IsNullOrWhiteSpace(note)))
        {
            throw new ArgumentException("Resolution requires a note of up to 1,000 characters.");
        }

        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var status = await GetStatusAsync(connection, transaction, alertId, cancellationToken);
        if (status is null)
        {
            return null;
        }

        if (status == "resolved")
        {
            throw new InvalidOperationException("This alert has already been resolved.");
        }

        if (action == "reviewed" && status == "reviewed")
        {
            throw new InvalidOperationException("This alert has already been reviewed.");
        }

        var occurredAt = now.ToUniversalTime();
        await InsertActionAsync(
            connection, transaction, alertId, action, actorUserId, actorName,
            string.IsNullOrWhiteSpace(note) ? null : note.Trim(), occurredAt, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(alertId, cancellationToken);
    }

    private async Task RecordSignalAsync(
        string signalType,
        string signalKey,
        string? actorUserId,
        string? workstationId,
        string? resourceId,
        int threshold,
        DateTimeOffset now,
        string alertType,
        string severity,
        string summary,
        string details,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var occurredAt = now.ToUniversalTime();
        var insertSignal = connection.CreateCommand();
        insertSignal.Transaction = transaction;
        insertSignal.CommandText =
            "INSERT INTO alert_signal_events(signal_id,signal_type,signal_key,actor_user_id,workstation_id,resource_id,occurred_at) " +
            "VALUES($id,$type,$key,$actor,$device,$resource,$at);";
        insertSignal.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
        insertSignal.Parameters.AddWithValue("$type", signalType);
        insertSignal.Parameters.AddWithValue("$key", signalKey);
        insertSignal.Parameters.AddWithValue("$actor", (object?)actorUserId ?? DBNull.Value);
        insertSignal.Parameters.AddWithValue("$device", (object?)workstationId ?? DBNull.Value);
        insertSignal.Parameters.AddWithValue("$resource", (object?)resourceId ?? DBNull.Value);
        insertSignal.Parameters.AddWithValue("$at", occurredAt.ToString("O"));
        await insertSignal.ExecuteNonQueryAsync(cancellationToken);

        var windowStart = (occurredAt - SignalWindow).ToString("O");
        var countCommand = connection.CreateCommand();
        countCommand.Transaction = transaction;
        countCommand.CommandText =
            "SELECT COUNT(*) FROM alert_signal_events WHERE signal_type=$type AND signal_key=$key AND occurred_at >= $start;";
        countCommand.Parameters.AddWithValue("$type", signalType);
        countCommand.Parameters.AddWithValue("$key", signalKey);
        countCommand.Parameters.AddWithValue("$start", windowStart);
        var count = Convert.ToInt32(await countCommand.ExecuteScalarAsync(cancellationToken));
        if (count >= threshold)
        {
            var dedupeKey = $"{alertType}:{signalKey}";
            await CreateAlertUnlessRecentAsync(
                connection, transaction, alertType, severity, summary,
                $"{details} Observed signal count: {count}.",
                actorUserId, workstationId,
                signalType == "successful_export" ? "paper" : "network_source",
                resourceId ?? signalKey,
                dedupeKey,
                occurredAt,
                cancellationToken);
        }

        var prune = connection.CreateCommand();
        prune.Transaction = transaction;
        prune.CommandText = "DELETE FROM alert_signal_events WHERE occurred_at < $cutoff;";
        prune.Parameters.AddWithValue("$cutoff", (occurredAt - TimeSpan.FromDays(1)).ToString("O"));
        await prune.ExecuteNonQueryAsync(cancellationToken);
        var excess = connection.CreateCommand();
        excess.Transaction = transaction;
        excess.CommandText =
            "DELETE FROM alert_signal_events WHERE signal_id IN (" +
            "SELECT signal_id FROM alert_signal_events ORDER BY occurred_at DESC LIMIT -1 OFFSET $limit);";
        excess.Parameters.AddWithValue("$limit", MaxSignals);
        await excess.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private async Task CreateAlertUnlessRecentAsync(
        string alertType,
        string severity,
        string summary,
        string details,
        string? actorUserId,
        string? workstationId,
        string? resourceType,
        string? resourceId,
        string dedupeKey,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        await CreateAlertUnlessRecentAsync(
            connection, transaction, alertType, severity, summary, details, actorUserId,
            workstationId, resourceType, resourceId, dedupeKey, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task CreateAlertUnlessRecentAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string alertType,
        string severity,
        string summary,
        string details,
        string? actorUserId,
        string? workstationId,
        string? resourceType,
        string? resourceId,
        string dedupeKey,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var existing = connection.CreateCommand();
        existing.Transaction = transaction;
        existing.CommandText =
            "SELECT 1 FROM security_alerts WHERE dedupe_key=$key AND created_at >= $cutoff LIMIT 1;";
        existing.Parameters.AddWithValue("$key", dedupeKey);
        existing.Parameters.AddWithValue("$cutoff", (now - SignalWindow).ToUniversalTime().ToString("O"));
        if (await existing.ExecuteScalarAsync(cancellationToken) is not null)
        {
            return;
        }

        var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            "INSERT INTO security_alerts(alert_id,alert_type,severity,summary,details,actor_user_id,workstation_id," +
            "resource_type,resource_id,created_at,dedupe_key) " +
            "VALUES($id,$type,$severity,$summary,$details,$actor,$device,$resourceType,$resourceId,$created,$dedupe);";
        insert.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
        insert.Parameters.AddWithValue("$type", alertType);
        insert.Parameters.AddWithValue("$severity", severity);
        insert.Parameters.AddWithValue("$summary", summary);
        insert.Parameters.AddWithValue("$details", details);
        insert.Parameters.AddWithValue("$actor", (object?)actorUserId ?? DBNull.Value);
        insert.Parameters.AddWithValue("$device", (object?)workstationId ?? DBNull.Value);
        insert.Parameters.AddWithValue("$resourceType", (object?)resourceType ?? DBNull.Value);
        insert.Parameters.AddWithValue("$resourceId", (object?)resourceId ?? DBNull.Value);
        insert.Parameters.AddWithValue("$created", now.ToUniversalTime().ToString("O"));
        insert.Parameters.AddWithValue("$dedupe", dedupeKey);
        await insert.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<string?> GetStatusAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string alertId,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT (SELECT action FROM security_alert_actions WHERE alert_id=$id AND action IN ('reviewed','resolved') " +
            "ORDER BY occurred_at DESC LIMIT 1) FROM security_alerts WHERE alert_id=$id;";
        command.Parameters.AddWithValue("$id", alertId);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null or DBNull ? (result is DBNull ? "open" : null) : (string)result;
    }

    private const string AlertSelect =
        "SELECT a.alert_id,a.alert_type,a.severity,a.summary,a.details,a.actor_user_id,a.workstation_id," +
        "a.resource_type,a.resource_id,a.created_at," +
        "COALESCE((SELECT action FROM security_alert_actions x WHERE x.alert_id=a.alert_id " +
        "AND x.action IN ('reviewed','resolved') ORDER BY x.occurred_at DESC LIMIT 1),'open')," +
        "(SELECT actor_user_id FROM security_alert_actions x WHERE x.alert_id=a.alert_id AND x.action='reviewed' ORDER BY x.occurred_at LIMIT 1)," +
        "(SELECT actor_name FROM security_alert_actions x WHERE x.alert_id=a.alert_id AND x.action='reviewed' ORDER BY x.occurred_at LIMIT 1)," +
        "(SELECT occurred_at FROM security_alert_actions x WHERE x.alert_id=a.alert_id AND x.action='reviewed' ORDER BY x.occurred_at LIMIT 1)," +
        "(SELECT actor_user_id FROM security_alert_actions x WHERE x.alert_id=a.alert_id AND x.action='resolved' ORDER BY x.occurred_at DESC LIMIT 1)," +
        "(SELECT actor_name FROM security_alert_actions x WHERE x.alert_id=a.alert_id AND x.action='resolved' ORDER BY x.occurred_at DESC LIMIT 1)," +
        "(SELECT occurred_at FROM security_alert_actions x WHERE x.alert_id=a.alert_id AND x.action='resolved' ORDER BY x.occurred_at DESC LIMIT 1)," +
        "(SELECT note FROM security_alert_actions x WHERE x.alert_id=a.alert_id AND x.action='reviewed' ORDER BY x.occurred_at DESC LIMIT 1) " +
        "FROM security_alerts a";

    private static SecurityAlert ReadAlert(SqliteDataReader reader) =>
        new(
            reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetString(6),
            reader.IsDBNull(7) ? null : reader.GetString(7),
            reader.IsDBNull(8) ? null : reader.GetString(8),
            DateTimeOffset.Parse(reader.GetString(9)),
            reader.GetString(10),
            reader.IsDBNull(11) ? null : reader.GetString(11),
            reader.IsDBNull(12) ? null : reader.GetString(12),
            reader.IsDBNull(13) ? null : DateTimeOffset.Parse(reader.GetString(13)),
            reader.IsDBNull(14) ? null : reader.GetString(14),
            reader.IsDBNull(15) ? null : reader.GetString(15),
            reader.IsDBNull(16) ? null : DateTimeOffset.Parse(reader.GetString(16)),
            reader.IsDBNull(17) ? null : reader.GetString(17));

    private static async Task InsertActionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string alertId,
        string action,
        string actorUserId,
        string actorName,
        string? note,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            "INSERT INTO security_alert_actions(action_id,alert_id,action,actor_user_id,actor_name,note,occurred_at) " +
            "VALUES($id,$alert,$action,$user,$name,$note,$occurred);";
        insert.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N"));
        insert.Parameters.AddWithValue("$alert", alertId);
        insert.Parameters.AddWithValue("$action", action);
        insert.Parameters.AddWithValue("$user", actorUserId);
        insert.Parameters.AddWithValue("$name", actorName);
        insert.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
        insert.Parameters.AddWithValue("$occurred", now.ToUniversalTime().ToString("O"));
        await insert.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (!_initialized)
        {
            await InitializeAsync(cancellationToken);
        }
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static string Limit(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];
}
