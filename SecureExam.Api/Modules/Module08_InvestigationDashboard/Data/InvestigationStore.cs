using Microsoft.Data.Sqlite;
using SecureExam.Api.Models;

namespace SecureExam.Api.Data;

internal sealed class InvestigationStore
{
    private const int MaxHistoryEvents = 1000;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private bool _initialized;

    public InvestigationStore(IConfiguration configuration)
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
                "CREATE TABLE IF NOT EXISTS investigation_incidents(" +
                "incident_id TEXT PRIMARY KEY,summary TEXT NOT NULL,paper_id TEXT NULL,copy_id TEXT NULL," +
                "created_by TEXT NOT NULL,created_at TEXT NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_investigation_incidents_paper ON investigation_incidents(paper_id);" +
                "CREATE INDEX IF NOT EXISTS idx_investigation_incidents_copy ON investigation_incidents(copy_id);" +
                "CREATE TRIGGER IF NOT EXISTS investigation_incidents_no_update BEFORE UPDATE ON investigation_incidents " +
                "BEGIN SELECT RAISE(ABORT,'investigation incidents are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS investigation_incidents_no_delete BEFORE DELETE ON investigation_incidents " +
                "BEGIN SELECT RAISE(ABORT,'investigation incidents are append-only'); END;";
            await command.ExecuteNonQueryAsync(cancellationToken);
            _initialized = true;
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    public async Task<InvestigationIncident> CreateIncidentAsync(
        CreateInvestigationIncidentRequest request,
        string createdBy,
        string createdByName,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var summary = request.Summary?.Trim();
        var paperId = NormalizeOptional(request.PaperId);
        var copyId = NormalizeOptional(request.CopyId);
        if (string.IsNullOrWhiteSpace(summary) || summary.Length > 1000 ||
            (paperId is null && copyId is null) ||
            (paperId is not null && paperId.Length > 100) ||
            (copyId is not null && copyId.Length > 100))
        {
            throw new ArgumentException("Provide a summary of up to 1,000 characters and link a paper ID or copy ID.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        if (copyId is not null)
        {
            var copyCommand = connection.CreateCommand();
            copyCommand.Transaction = transaction;
            copyCommand.CommandText = "SELECT paper_id FROM issued_paper_copies WHERE copy_id=$copy;";
            copyCommand.Parameters.AddWithValue("$copy", copyId);
            var linkedPaperId = await copyCommand.ExecuteScalarAsync(cancellationToken) as string;
            if (linkedPaperId is null)
            {
                throw new ArgumentException("The copy ID does not match an issued paper copy.");
            }

            if (paperId is not null && !string.Equals(paperId, linkedPaperId, StringComparison.Ordinal))
            {
                throw new ArgumentException("The paper ID does not match the selected issued copy.");
            }

            paperId = linkedPaperId;
        }

        if (paperId is not null)
        {
            var paperCommand = connection.CreateCommand();
            paperCommand.Transaction = transaction;
            paperCommand.CommandText = "SELECT 1 FROM papers WHERE paper_id=$paper;";
            paperCommand.Parameters.AddWithValue("$paper", paperId);
            if (await paperCommand.ExecuteScalarAsync(cancellationToken) is null)
            {
                throw new ArgumentException("The paper ID was not found.");
            }
        }

        var incidentId = Guid.NewGuid().ToString("N");
        var createdAt = now.ToUniversalTime();
        var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            "INSERT INTO investigation_incidents(incident_id,summary,paper_id,copy_id,created_by,created_at) " +
            "VALUES($id,$summary,$paper,$copy,$user,$created);";
        insert.Parameters.AddWithValue("$id", incidentId);
        insert.Parameters.AddWithValue("$summary", summary);
        insert.Parameters.AddWithValue("$paper", (object?)paperId ?? DBNull.Value);
        insert.Parameters.AddWithValue("$copy", (object?)copyId ?? DBNull.Value);
        insert.Parameters.AddWithValue("$user", createdBy);
        insert.Parameters.AddWithValue("$created", createdAt.ToString("O"));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new InvestigationIncident(incidentId, summary, paperId, copyId, createdBy, createdByName, createdAt);
    }

    public async Task<InvestigationEvidenceReport> SearchAsync(
        string searchType,
        string searchValue,
        DateTimeOffset generatedAt,
        bool auditChainValid,
        long auditEventsChecked,
        string auditChainAssessment,
        CancellationToken cancellationToken)
    {
        var normalizedValue = searchValue.Trim();
        if (normalizedValue.Length is < 1 or > 200 ||
            searchType is not ("paper" or "copy" or "incident"))
        {
            throw new ArgumentException("Search by a paper ID, copy ID, or incident ID (up to 200 characters).");
        }

        await using var connection = await OpenAsync(cancellationToken);
        var incidents = new List<InvestigationIncident>();
        string? paperId = null;
        string? copyId = null;

        if (searchType == "incident")
        {
            var incidentCommand = connection.CreateCommand();
            incidentCommand.CommandText =
                "SELECT i.incident_id,i.summary,i.paper_id,i.copy_id,i.created_by,u.display_name,i.created_at " +
                "FROM investigation_incidents i LEFT JOIN users u ON u.user_id=i.created_by " +
                "WHERE i.incident_id=$incident COLLATE NOCASE;";
            incidentCommand.Parameters.AddWithValue("$incident", normalizedValue);
            await using var reader = await incidentCommand.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                incidents.Add(new InvestigationIncident(
                    reader.GetString(0), reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.GetString(4), reader.IsDBNull(5) ? "Unknown user" : reader.GetString(5),
                    DateTimeOffset.Parse(reader.GetString(6))));
                paperId = incidents[0].PaperId;
                copyId = incidents[0].CopyId;
            }
        }
        else if (searchType == "paper")
        {
            paperId = normalizedValue;
        }
        else
        {
            copyId = normalizedValue;
        }

        if (searchType != "incident" || paperId is not null || copyId is not null)
        {
            await LoadRelatedIncidentsAsync(connection, searchType, normalizedValue, paperId, copyId, incidents, cancellationToken);
        }

        if (searchType == "copy" && copyId is not null)
        {
            var resolveCopy = connection.CreateCommand();
            resolveCopy.CommandText = "SELECT paper_id FROM issued_paper_copies WHERE copy_id=$copy;";
            resolveCopy.Parameters.AddWithValue("$copy", copyId);
            paperId = await resolveCopy.ExecuteScalarAsync(cancellationToken) as string;
            if (paperId is not null)
            {
                await LoadRelatedIncidentsAsync(connection, "copy", normalizedValue, paperId, copyId, incidents, cancellationToken);
            }
        }

        string? paperTitle = null;
        string? paperStatus = null;
        int? paperVersion = null;
        if (paperId is not null)
        {
            var paperCommand = connection.CreateCommand();
            paperCommand.CommandText = "SELECT title,version,status FROM papers WHERE paper_id=$paper;";
            paperCommand.Parameters.AddWithValue("$paper", paperId);
            await using var reader = await paperCommand.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                paperTitle = reader.GetString(0);
                paperVersion = reader.GetInt32(1);
                paperStatus = reader.GetString(2);
            }
        }

        var copies = await LoadCopiesAsync(connection, paperId, copyId, cancellationToken);
        var history = await LoadHistoryAsync(connection, paperId, copies, cancellationToken);
        var resultsTruncated = history.Count > MaxHistoryEvents || copies.Count > 1000;
        if (resultsTruncated)
        {
            if (history.Count > MaxHistoryEvents)
            {
                history.RemoveRange(MaxHistoryEvents, history.Count - MaxHistoryEvents);
            }

            if (copies.Count > 1000)
            {
                copies.RemoveRange(1000, copies.Count - 1000);
            }
        }

        var missing = new List<string>();
        if (searchType == "incident" && incidents.All(incident =>
                string.Equals(incident.IncidentId, normalizedValue, StringComparison.OrdinalIgnoreCase)))
        {
            missing.Add("No incident record matched this ID.");
        }
        if (paperId is null)
        {
            missing.Add(searchType == "copy"
                ? "No issued-copy record matched this copy ID."
                : "The incident has no linked paper ID.");
        }
        if (paperId is not null && copies.Count == 0)
        {
            missing.Add("No issued-copy records were found for the linked paper.");
        }
        if (history.Count == 0)
        {
            missing.Add("No matching audit history was found for the linked paper.");
        }
        if (history.Any(item => string.IsNullOrWhiteSpace(item.WorkstationId)))
        {
            missing.Add("Some audit events have no registered workstation identity.");
        }
        if (history.Any(item => !string.IsNullOrWhiteSpace(item.WorkstationId) &&
                                (string.IsNullOrWhiteSpace(item.Centre) ||
                                 string.Equals(item.Centre, "Unassigned", StringComparison.OrdinalIgnoreCase) ||
                                 string.IsNullOrWhiteSpace(item.Room) ||
                                 string.Equals(item.Room, "Unassigned", StringComparison.OrdinalIgnoreCase) ||
                                 string.IsNullOrWhiteSpace(item.AssignedWorkstationId) ||
                                 string.Equals(item.AssignedWorkstationId, "Unassigned", StringComparison.OrdinalIgnoreCase))))
        {
            missing.Add("Some workstation identities are not mapped to a registered centre and room.");
        }
        if (resultsTruncated)
        {
            missing.Add($"Audit history exceeds the {MaxHistoryEvents}-event report limit.");
        }
        if (copies.Any(copy => copy.PdfSha256 is null))
        {
            missing.Add("At least one issued copy has no registered PDF fingerprint.");
        }
        if (!auditChainValid)
        {
            missing.Add("The stored audit chain did not verify successfully.");
        }

        var limitations = new[]
        {
            "Audit chain verification checks the current database only; it is not independently anchored and cannot rule out a privileged database rewrite or tail truncation.",
            "An audit event records a server-side request, not proof that a person viewed content or that a physical printer completed a job.",
            "Workstation centre/room mapping is based on the device registration currently stored in the database; historical location changes are not versioned.",
            "A registered device ID and client-reported compliance indicators are not tamper-resistant hardware attestation.",
            "PDF tracing uses exact-file SHA-256 fingerprints; modified files, screenshots, scans, and printed pages are not matched.",
            "Incident summaries are user-entered reports and are not independently verified by the system.",
            "Incident rows use database-level append-only guards but are not independently hash-chained or immutably anchored; exported JSON reports are unsigned and can be altered after export.",
            "This report includes records available in this database at generation time and does not establish completeness of external logs, backups, or evidence custody."
        };

        return new InvestigationEvidenceReport(
            searchType,
            normalizedValue,
            generatedAt.ToUniversalTime(),
            paperId,
            paperTitle,
            paperVersion,
            paperStatus,
            incidents.DistinctBy(incident => incident.IncidentId).ToArray(),
            copies,
            history,
            auditChainValid,
            auditEventsChecked,
            auditChainAssessment,
            resultsTruncated,
            missing.Distinct(StringComparer.Ordinal).ToArray(),
            limitations);
    }

    private static async Task LoadRelatedIncidentsAsync(
        SqliteConnection connection,
        string searchType,
        string searchValue,
        string? paperId,
        string? copyId,
        List<InvestigationIncident> incidents,
        CancellationToken cancellationToken)
    {
        if (searchType == "incident" && paperId is null && copyId is null)
        {
            return;
        }

        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT i.incident_id,i.summary,i.paper_id,i.copy_id,i.created_by,u.display_name,i.created_at " +
            "FROM investigation_incidents i LEFT JOIN users u ON u.user_id=i.created_by WHERE " +
            "(i.incident_id=$query COLLATE NOCASE) OR ($paper IS NOT NULL AND i.paper_id=$paper) " +
            "OR ($copy IS NOT NULL AND i.copy_id=$copy) ORDER BY i.created_at DESC LIMIT 200;";
        command.Parameters.AddWithValue("$query", searchValue);
        command.Parameters.AddWithValue("$paper", (object?)paperId ?? DBNull.Value);
        command.Parameters.AddWithValue("$copy", (object?)copyId ?? DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            incidents.Add(new InvestigationIncident(
                reader.GetString(0), reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.GetString(4), reader.IsDBNull(5) ? "Unknown user" : reader.GetString(5),
                DateTimeOffset.Parse(reader.GetString(6))));
        }
    }

    private static async Task<List<InvestigationCopyEvidence>> LoadCopiesAsync(
        SqliteConnection connection,
        string? paperId,
        string? copyId,
        CancellationToken cancellationToken)
    {
        if (paperId is null && copyId is null)
        {
            return new List<InvestigationCopyEvidence>();
        }

        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT c.copy_id,c.paper_id,p.title,f.paper_version,c.recipient_user_id,u.display_name,u.email," +
            "c.action,c.issued_at,c.content_sha256,f.pdf_sha256 FROM issued_paper_copies c " +
            "JOIN papers p ON p.paper_id=c.paper_id LEFT JOIN users u ON u.user_id=c.recipient_user_id " +
            "LEFT JOIN document_fingerprints f ON f.copy_id=c.copy_id " +
            "WHERE ($paper IS NOT NULL AND c.paper_id=$paper) OR ($copy IS NOT NULL AND c.copy_id=$copy) " +
            "ORDER BY c.issued_at DESC LIMIT 1001;";
        command.Parameters.AddWithValue("$paper", (object?)paperId ?? DBNull.Value);
        command.Parameters.AddWithValue("$copy", (object?)copyId ?? DBNull.Value);
        var copies = new List<InvestigationCopyEvidence>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            copies.Add(new InvestigationCopyEvidence(
                reader.GetString(0), reader.GetString(1), reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetInt32(3),
                reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.GetString(7), DateTimeOffset.Parse(reader.GetString(8)),
                reader.GetString(9), reader.IsDBNull(10) ? null : reader.GetString(10)));
        }

        return copies;
    }

    private static async Task<List<InvestigationAuditEntry>> LoadHistoryAsync(
        SqliteConnection connection,
        string? paperId,
        IReadOnlyList<InvestigationCopyEvidence> copies,
        CancellationToken cancellationToken)
    {
        if (paperId is null)
        {
            return new List<InvestigationAuditEntry>();
        }

        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT a.sequence,a.event_id,a.server_timestamp,a.event_type,a.user_id,a.workstation_id," +
            "d.name,d.centre,d.room,d.workstation_id,a.resource_type,a.resource_id,a.outcome,a.details,a.event_hash " +
            "FROM audit_events a LEFT JOIN devices d ON d.device_id=a.workstation_id " +
            "WHERE a.resource_id=$paper OR (a.resource_type='paper' AND a.resource_id=$paper) " +
            "ORDER BY a.sequence DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$paper", paperId);
        command.Parameters.AddWithValue("$limit", MaxHistoryEvents + 1);
        var history = new List<InvestigationAuditEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            history.Add(new InvestigationAuditEntry(
                reader.GetInt64(0), reader.GetString(1), DateTimeOffset.Parse(reader.GetString(2)),
                reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetString(9),
                reader.IsDBNull(10) ? null : reader.GetString(10),
                reader.IsDBNull(11) ? null : reader.GetString(11),
                reader.GetString(12), reader.GetString(13), reader.GetString(14)));
        }

        return history;
    }

    private static string? NormalizeOptional(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}
