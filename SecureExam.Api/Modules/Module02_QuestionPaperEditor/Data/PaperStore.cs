using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using SecureExam.Api.Models;

namespace SecureExam.Api.Data;

internal sealed class PaperStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;
    private readonly IDataProtector _paperProtector;
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private bool _initialized;

    public PaperStore(IConfiguration configuration, IDataProtectionProvider protectionProvider)
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
        _paperProtector = protectionProvider.CreateProtector("SecureExam.Papers.Payload.v1");
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
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

            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            var command = connection.CreateCommand();
            command.CommandText =
                "PRAGMA secure_delete=ON;" +
                "CREATE TABLE IF NOT EXISTS papers (" +
                "paper_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, title TEXT NOT NULL, subject TEXT NOT NULL, " +
                "exam_code TEXT NOT NULL, sections_json TEXT NOT NULL, total_marks INTEGER NOT NULL, " +
                "instructions TEXT NOT NULL, content_json TEXT NOT NULL, " +
                "status TEXT NOT NULL CHECK(status IN ('draft','submitted','approved','changes_requested')), " +
                "version INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, " +
                "submitted_at TEXT NULL, approved_at TEXT NULL, approved_by TEXT NULL, protected_payload TEXT NULL);" +
                "CREATE TABLE IF NOT EXISTS paper_distribution_grants (" +
                "grant_id TEXT PRIMARY KEY,paper_id TEXT NOT NULL,recipient_user_id TEXT NOT NULL,granted_by TEXT NOT NULL," +
                "issued_at TEXT NOT NULL,expires_at TEXT NULL,revoked_at TEXT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_distribution_grants_recipient ON paper_distribution_grants(recipient_user_id,paper_id);" +
                "CREATE TABLE IF NOT EXISTS issued_paper_copies (" +
                "copy_id TEXT PRIMARY KEY,paper_id TEXT NOT NULL,recipient_user_id TEXT NOT NULL,grant_id TEXT NULL," +
                "action TEXT NOT NULL CHECK(action IN ('view','export','print')),issued_at TEXT NOT NULL,content_sha256 TEXT NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_issued_copies_paper ON issued_paper_copies(paper_id,issued_at DESC);" +
                "CREATE TRIGGER IF NOT EXISTS issued_copies_no_update BEFORE UPDATE ON issued_paper_copies " +
                "BEGIN SELECT RAISE(ABORT,'issued paper copies are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS issued_copies_no_delete BEFORE DELETE ON issued_paper_copies " +
                "BEGIN SELECT RAISE(ABORT,'issued paper copies are append-only'); END;" +
                "CREATE INDEX IF NOT EXISTS idx_papers_owner ON papers(owner_id);" +
                "CREATE INDEX IF NOT EXISTS idx_papers_status ON papers(status);" +
                "CREATE TABLE IF NOT EXISTS paper_versions (" +
                "paper_id TEXT NOT NULL, version INTEGER NOT NULL, action TEXT NOT NULL, " +
                "changed_by TEXT NOT NULL, changed_at TEXT NOT NULL, snapshot_json TEXT NOT NULL, protected_snapshot TEXT NULL, " +
                "PRIMARY KEY(paper_id,version));" +
                "CREATE TABLE IF NOT EXISTS paper_access_events (" +
                "event_id TEXT PRIMARY KEY, paper_id TEXT NOT NULL, paper_title TEXT NOT NULL, user_id TEXT NOT NULL, " +
                "action TEXT NOT NULL CHECK(action IN ('export','print')), content_sha256 TEXT NOT NULL, occurred_at TEXT NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_paper_access_events_time ON paper_access_events(occurred_at);";
            await command.ExecuteNonQueryAsync(cancellationToken);
            await EnsureColumnAsync(connection, "papers", "protected_payload", "TEXT NULL", cancellationToken);
            await EnsureColumnAsync(connection, "papers", "reviewer_comment", "TEXT NULL", cancellationToken);
            await EnsureColumnAsync(connection, "papers", "reviewer_decision", "TEXT NULL", cancellationToken);
            await EnsureColumnAsync(connection, "paper_versions", "protected_snapshot", "TEXT NULL", cancellationToken);
            var migrated = await MigratePlaintextAsync(connection, cancellationToken);
            var cleanup = connection.CreateCommand();
            cleanup.CommandText = migrated
                ? "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
                : "PRAGMA wal_checkpoint(TRUNCATE);";
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
            _initialized = true;
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    public async Task<IReadOnlyList<PaperAccessEvent>> ListAccessEventsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT e.event_id,e.paper_id,e.paper_title,e.user_id,u.display_name,e.action,e.content_sha256,e.occurred_at " +
            "FROM paper_access_events e JOIN users u ON u.user_id=e.user_id ORDER BY e.occurred_at DESC LIMIT 500;";
        var events = new List<PaperAccessEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(new PaperAccessEvent(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                DateTimeOffset.Parse(reader.GetString(7))));
        }

        return events;
    }

    public async Task<IReadOnlyList<DistributionGrant>> ListDistributionGrantsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT g.grant_id,g.paper_id,p.title,g.recipient_user_id,u.display_name,u.email,g.granted_by," +
            "g.issued_at,g.expires_at,g.revoked_at FROM paper_distribution_grants g " +
            "JOIN papers p ON p.paper_id=g.paper_id JOIN users u ON u.user_id=g.recipient_user_id " +
            "ORDER BY g.issued_at DESC LIMIT 1000;";
        var grants = new List<DistributionGrant>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            grants.Add(new DistributionGrant(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                DateTimeOffset.Parse(reader.GetString(7)),
                reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8)),
                reader.IsDBNull(9) ? null : DateTimeOffset.Parse(reader.GetString(9))));
        }

        return grants;
    }

    public async Task<DistributionGrant?> CreateDistributionGrantAsync(
        string paperId,
        string recipientUserId,
        string grantedBy,
        DateTimeOffset? expiresAt,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(recipientUserId) || recipientUserId.Length > 100 ||
            (expiresAt is not null && expiresAt <= now))
        {
            throw new ArgumentException("Select a valid recipient and a future expiry time.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var paperCommand = connection.CreateCommand();
        paperCommand.Transaction = transaction;
        paperCommand.CommandText =
            "SELECT title,status FROM papers WHERE paper_id=$paper;";
        paperCommand.Parameters.AddWithValue("$paper", paperId);
        await using var paperReader = await paperCommand.ExecuteReaderAsync(cancellationToken);
        if (!await paperReader.ReadAsync(cancellationToken) || paperReader.GetString(1) != "approved")
        {
            return null;
        }

        var paperTitle = paperReader.GetString(0);
        await paperReader.DisposeAsync();

        var userCommand = connection.CreateCommand();
        userCommand.Transaction = transaction;
        userCommand.CommandText =
            "SELECT display_name,email FROM users WHERE user_id=$user AND status='active';";
        userCommand.Parameters.AddWithValue("$user", recipientUserId);
        await using var userReader = await userCommand.ExecuteReaderAsync(cancellationToken);
        if (!await userReader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var recipientName = userReader.GetString(0);
        var recipientEmail = userReader.GetString(1);
        await userReader.DisposeAsync();

        var grantId = Guid.NewGuid().ToString("N");
        var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            "INSERT INTO paper_distribution_grants(grant_id,paper_id,recipient_user_id,granted_by,issued_at,expires_at) " +
            "VALUES($grant,$paper,$recipient,$grantedBy,$issued,$expires);";
        insert.Parameters.AddWithValue("$grant", grantId);
        insert.Parameters.AddWithValue("$paper", paperId);
        insert.Parameters.AddWithValue("$recipient", recipientUserId);
        insert.Parameters.AddWithValue("$grantedBy", grantedBy);
        insert.Parameters.AddWithValue("$issued", now.ToString("O"));
        insert.Parameters.AddWithValue("$expires", (object?)expiresAt?.ToUniversalTime().ToString("O") ?? DBNull.Value);
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new DistributionGrant(
            grantId, paperId, paperTitle, recipientUserId, recipientName, recipientEmail, grantedBy, now, expiresAt, null);
    }

    public async Task<bool> RevokeDistributionGrantAsync(
        string grantId,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "UPDATE paper_distribution_grants SET revoked_at=$revoked " +
            "WHERE grant_id=$grant AND revoked_at IS NULL;";
        command.Parameters.AddWithValue("$revoked", revokedAt.ToString("O"));
        command.Parameters.AddWithValue("$grant", grantId);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<IReadOnlyList<IssuedPaperCopy>> ListIssuedCopiesAsync(
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT copy_id,paper_id,recipient_user_id,action,issued_at,content_sha256 " +
            "FROM issued_paper_copies ORDER BY issued_at DESC LIMIT $limit;";
        command.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
        var copies = new List<IssuedPaperCopy>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            copies.Add(new IssuedPaperCopy(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                DateTimeOffset.Parse(reader.GetString(4)),
                reader.GetString(5)));
        }

        return copies;
    }

    public async Task<(PaperSummary? Paper, string? ContentSha256, string? CopyId)> GetApprovedForAccessAsync(
        string paperId,
        string userId,
        string role,
        string action,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (action is not ("export" or "print"))
        {
            throw new ArgumentException("Unsupported document access action.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var paper = await GetAsync(connection, transaction, paperId, userId, role, now, cancellationToken);
        if (paper is null || paper.Status != "approved")
        {
            return (null, null, null);
        }

        var payload = ToPayload(paper);
        var canonicalPayload = JsonSerializer.Serialize(payload, JsonOptions);
        var contentHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalPayload)));
        var audit = connection.CreateCommand();
        audit.Transaction = transaction;
        var copyId = Guid.NewGuid().ToString("N");
        audit.CommandText =
            "INSERT INTO paper_access_events(event_id,paper_id,paper_title,user_id,action,content_sha256,occurred_at) " +
            "VALUES($event,$paper,$title,$user,$action,$hash,$occurred);";
        audit.Parameters.AddWithValue("$event", Guid.NewGuid().ToString("N"));
        audit.Parameters.AddWithValue("$paper", paper.PaperId);
        audit.Parameters.AddWithValue("$title", paper.Title);
        audit.Parameters.AddWithValue("$user", userId);
        audit.Parameters.AddWithValue("$action", action);
        audit.Parameters.AddWithValue("$hash", contentHash);
        audit.Parameters.AddWithValue("$occurred", now.ToString("O"));
        await audit.ExecuteNonQueryAsync(cancellationToken);
        await RecordIssuedCopyAsync(connection, transaction, copyId, paper, userId, action, contentHash, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return (paper with { IssuedCopyId = copyId }, contentHash, copyId);
    }

    public async Task<IReadOnlyList<PaperSummary>> ListAsync(
        string userId,
        string role,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT p.*,u.display_name FROM papers p JOIN users u ON u.user_id=p.owner_id " +
            "WHERE $role='admin' OR (p.owner_id=$user AND $role='setter' AND p.status!='approved') " +
            "OR ($role='reviewer' AND p.status='submitted') OR EXISTS(" +
            "SELECT 1 FROM paper_distribution_grants g WHERE g.paper_id=p.paper_id AND g.recipient_user_id=$user " +
            "AND p.status='approved' AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$now)) " +
            "ORDER BY p.updated_at DESC;";
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$user", userId);
        command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
        var results = new List<PaperSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var paper = ReadPaper(reader);
            results.Add(paper with
            {
                Instructions = string.Empty,
                Content = new PaperDocument(Array.Empty<PaperParagraph>()),
                IssuedCopyId = null
            });
        }

        return results;
    }

    public async Task<PaperSummary?> GetAsync(
        string paperId,
        string userId,
        string role,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await GetAsync(connection, null, paperId, userId, role, DateTimeOffset.UtcNow, cancellationToken);
    }

    public async Task<(PaperSummary? Paper, string? CopyId)> GetForViewAsync(
        string paperId,
        string userId,
        string role,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var paper = await GetAsync(connection, transaction, paperId, userId, role, now, cancellationToken);
        if (paper is null)
        {
            return (null, null);
        }

        var payload = ToPayload(paper);
        var canonicalPayload = JsonSerializer.Serialize(payload, JsonOptions);
        var contentHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalPayload)));
        var copyId = Guid.NewGuid().ToString("N");
        await RecordIssuedCopyAsync(connection, transaction, copyId, paper, userId, "view", contentHash, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return (paper with { IssuedCopyId = copyId }, copyId);
    }

    public async Task<IReadOnlyList<PaperVersionSummary>?> GetVersionsAsync(
        string paperId,
        string userId,
        string role,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var now = DateTimeOffset.UtcNow;
        var paper = await GetAsync(connection, transaction, paperId, userId, role, now, cancellationToken);
        if (paper is null)
        {
            return null;
        }

        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT v.version,v.action,v.changed_by,u.display_name,v.changed_at,v.protected_snapshot " +
            "FROM paper_versions v JOIN users u ON u.user_id=v.changed_by " +
            "WHERE v.paper_id=$paper ORDER BY v.version DESC;";
        command.Parameters.AddWithValue("$paper", paperId);
        var versions = new List<(int Version, string Action, string ChangedBy, DateTimeOffset ChangedAt, PaperSummary Snapshot)>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                if (reader.IsDBNull(5))
                {
                    throw new PaperIntegrityException("The encrypted version snapshot is missing.");
                }

                versions.Add((
                    reader.GetInt32(0),
                    reader.GetString(1),
                    reader.GetString(3),
                    DateTimeOffset.Parse(reader.GetString(4)),
                    Unprotect<PaperSummary>(reader.GetString(5))));
            }
        }

        var results = new List<PaperVersionSummary>(versions.Count);
        foreach (var version in versions)
        {
            var copyId = Guid.NewGuid().ToString("N");
            var canonicalPayload = JsonSerializer.Serialize(ToPayload(version.Snapshot), JsonOptions);
            var contentHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalPayload)));
            await RecordIssuedCopyAsync(
                connection, transaction, copyId, version.Snapshot, userId, "view", contentHash, now, cancellationToken);
            results.Add(new PaperVersionSummary(
                version.Version,
                version.Action,
                version.ChangedBy,
                version.ChangedAt,
                version.Snapshot with { IssuedCopyId = copyId }));
        }

        await transaction.CommitAsync(cancellationToken);
        return results;
    }

    public async Task<PaperSummary> SaveDraftAsync(
        string? paperId,
        string userId,
        string role,
        PaperDraftRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        Validate(request);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var id = paperId ?? Guid.NewGuid().ToString("N");
        PaperSummary? current = null;
        if (paperId is not null)
        {
            current = await GetAsync(connection, transaction, paperId, userId, role, now, cancellationToken);
            if (current is null)
            {
                throw new KeyNotFoundException("Paper not found.");
            }

            if (!CanEdit(current, userId, role))
            {
                throw new UnauthorizedAccessException("This paper is read-only or belongs to another setter.");
            }
        }

        var ownerId = current?.OwnerId ?? userId;
        var ownerName = await GetDisplayNameAsync(connection, transaction, ownerId, cancellationToken);
        var version = (current?.Version ?? 0) + 1;
        var createdAt = current?.CreatedAt ?? now;
        var summary = new PaperSummary(
            id,
            ownerId,
            ownerName,
            request.Title.Trim(),
            request.Subject.Trim(),
            request.ExamCode.Trim(),
            request.Sections.Select(section => new PaperSection(section.Name.Trim(), section.Marks)).ToArray(),
            request.TotalMarks,
            request.Instructions.Trim(),
            request.Content,
            current?.Status ?? "draft",
            version,
            createdAt,
            now,
            current?.SubmittedAt,
            current?.ApprovedAt,
            current?.ApprovedBy);

        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = paperId is null
            ? "INSERT INTO papers(paper_id,owner_id,title,subject,exam_code,sections_json,total_marks,instructions,content_json,status,version,created_at,updated_at,protected_payload) " +
              "VALUES($id,$owner,$title,$subject,$code,'[]',$marks,'','', 'draft',$version,$created,$updated,$protected);"
            : "UPDATE papers SET title=$title,subject=$subject,exam_code=$code,sections_json='[]',total_marks=$marks," +
              "instructions='',content_json='',protected_payload=$protected,reviewer_comment=NULL,reviewer_decision=NULL," +
              "version=$version,updated_at=$updated " +
              "WHERE paper_id=$id AND version=$expected;";
        AddPaperParameters(command, summary);
        command.Parameters.AddWithValue("$expected", current?.Version ?? 0);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("This paper changed elsewhere. Refresh it before saving again.");
        }

        await RecordVersionAsync(connection, transaction, summary, userId,
            current is null ? "created" : "autosaved", now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return summary;
    }

    public async Task<PaperSummary?> TransitionAsync(
        string paperId,
        string userId,
        string role,
        string action,
        string? comment,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (action is not ("submit" or "approve" or "reject" or "request_changes"))
        {
            throw new ArgumentException("Unsupported paper action.");
        }
        if (comment?.Length > 1000 || (action == "reject" && string.IsNullOrWhiteSpace(comment)))
        {
            throw new ArgumentException("A rejection reason of up to 1,000 characters is required.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var current = await GetAsync(connection, transaction, paperId, userId, role, now, cancellationToken);
        if (current is null)
        {
            return null;
        }

        if (action == "submit" &&
            (!CanEdit(current, userId, role) || current.Status is not ("draft" or "changes_requested")))
        {
            throw new UnauthorizedAccessException("Only the paper setter can submit an editable draft.");
        }

        if (action == "approve" &&
            (role is not ("admin" or "reviewer") || current.Status != "submitted"))
        {
            throw new UnauthorizedAccessException("Only an administrator or reviewer can approve a submitted paper.");
        }

        if (action is "request_changes" or "reject" &&
            (role is not ("admin" or "reviewer") || current.Status != "submitted"))
        {
            throw new UnauthorizedAccessException("Only an administrator or reviewer can return a submitted paper.");
        }

        var status = action switch
        {
            "submit" => "submitted",
            "approve" => "approved",
            _ => "changes_requested"
        };
        var version = current.Version + 1;
        var approvedAt = action == "approve" ? now : current.ApprovedAt;
        var approvedBy = action == "approve" ? userId : current.ApprovedBy;
        var submittedAt = action == "submit" ? now : current.SubmittedAt;
        var updated = current with
        {
            Status = status,
            Version = version,
            UpdatedAt = now,
            SubmittedAt = submittedAt,
            ApprovedAt = approvedAt,
            ApprovedBy = approvedBy,
            ReviewerComment = action is "request_changes" or "reject" ? comment?.Trim() : null,
            ReviewerDecision = action is "request_changes" or "reject" ? action : null
        };
        var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText =
            "UPDATE papers SET status=$status,version=$version,updated_at=$updated,submitted_at=$submitted," +
            "approved_at=$approved,approved_by=$approver,reviewer_comment=$comment," +
            "reviewer_decision=$decision WHERE paper_id=$id AND version=$expected;";
        update.Parameters.AddWithValue("$status", status);
        update.Parameters.AddWithValue("$version", version);
        update.Parameters.AddWithValue("$updated", now.ToString("O"));
        update.Parameters.AddWithValue("$submitted", (object?)submittedAt?.ToString("O") ?? DBNull.Value);
        update.Parameters.AddWithValue("$approved", (object?)approvedAt?.ToString("O") ?? DBNull.Value);
        update.Parameters.AddWithValue("$approver", (object?)approvedBy ?? DBNull.Value);
        update.Parameters.AddWithValue("$comment", action is "request_changes" or "reject"
            ? (object?)updated.ReviewerComment ?? DBNull.Value
            : (object?)current.ReviewerComment ?? DBNull.Value);
        update.Parameters.AddWithValue("$decision", (object?)updated.ReviewerDecision ?? DBNull.Value);
        update.Parameters.AddWithValue("$id", paperId);
        update.Parameters.AddWithValue("$expected", current.Version);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("This paper changed elsewhere. Refresh it before continuing.");
        }

        await RecordVersionAsync(connection, transaction, updated, userId, action, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return updated;
    }

    private async Task<PaperSummary?> GetAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string paperId,
        string userId,
        string role,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT p.*,u.display_name FROM papers p JOIN users u ON u.user_id=p.owner_id " +
            "WHERE p.paper_id=$paper AND ($role='admin' OR " +
            "(p.owner_id=$user AND $role='setter' AND p.status!='approved') OR " +
            "($role='reviewer' AND p.status='submitted') OR EXISTS(" +
            "SELECT 1 FROM paper_distribution_grants g WHERE g.paper_id=p.paper_id AND g.recipient_user_id=$user " +
            "AND p.status='approved' AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$now)));";
        command.Parameters.AddWithValue("$paper", paperId);
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$user", userId);
        command.Parameters.AddWithValue("$now", now.ToUniversalTime().ToString("O"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadPaper(reader) : null;
    }

    private static async Task RecordIssuedCopyAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string copyId,
        PaperSummary paper,
        string recipientUserId,
        string action,
        string contentHash,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var grantLookup = connection.CreateCommand();
        grantLookup.Transaction = transaction;
        grantLookup.CommandText =
            "SELECT grant_id FROM paper_distribution_grants WHERE paper_id=$paper AND recipient_user_id=$user " +
            "AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$now) ORDER BY issued_at DESC LIMIT 1;";
        grantLookup.Parameters.AddWithValue("$paper", paper.PaperId);
        grantLookup.Parameters.AddWithValue("$user", recipientUserId);
        grantLookup.Parameters.AddWithValue("$now", now.ToUniversalTime().ToString("O"));
        var grantId = await grantLookup.ExecuteScalarAsync(cancellationToken) as string;

        var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText =
            "INSERT INTO issued_paper_copies(copy_id,paper_id,recipient_user_id,grant_id,action,issued_at,content_sha256) " +
            "VALUES($copy,$paper,$user,$grant,$action,$issued,$hash);";
        insert.Parameters.AddWithValue("$copy", copyId);
        insert.Parameters.AddWithValue("$paper", paper.PaperId);
        insert.Parameters.AddWithValue("$user", recipientUserId);
        insert.Parameters.AddWithValue("$grant", (object?)grantId ?? DBNull.Value);
        insert.Parameters.AddWithValue("$action", action);
        insert.Parameters.AddWithValue("$issued", now.ToUniversalTime().ToString("O"));
        insert.Parameters.AddWithValue("$hash", contentHash);
        await insert.ExecuteNonQueryAsync(cancellationToken);
    }

    private PaperSummary ReadPaper(SqliteDataReader reader)
    {
        if (reader.IsDBNull(16))
        {
            throw new PaperIntegrityException("The encrypted paper payload is missing.");
        }

        var payload = Unprotect<ProtectedPaperPayload>(reader.GetString(16));
        if (payload.Title != reader.GetString(2) ||
            payload.Subject != reader.GetString(3) ||
            payload.ExamCode != reader.GetString(4) ||
            payload.TotalMarks != reader.GetInt32(6))
        {
            throw new PaperIntegrityException("Paper metadata integrity verification failed.");
        }

        return new PaperSummary(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(19),
            payload.Title,
            payload.Subject,
            payload.ExamCode,
            payload.Sections,
            payload.TotalMarks,
            payload.Instructions,
            payload.Content,
            reader.GetString(9),
            reader.GetInt32(10),
            DateTimeOffset.Parse(reader.GetString(11)),
            DateTimeOffset.Parse(reader.GetString(12)),
            reader.IsDBNull(13) ? null : DateTimeOffset.Parse(reader.GetString(13)),
            reader.IsDBNull(14) ? null : DateTimeOffset.Parse(reader.GetString(14)),
            reader.IsDBNull(15) ? null : reader.GetString(15))
        {
            ReviewerComment = reader.IsDBNull(17) ? null : reader.GetString(17),
            ReviewerDecision = reader.IsDBNull(18) ? null : reader.GetString(18)
        };
    }

    private async Task EnsureColumnAsync(
        SqliteConnection connection,
        string table,
        string column,
        string declaration,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info({table});";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.GetString(1) == column)
            {
                return;
            }
        }

        await reader.DisposeAsync();
        var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {declaration};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<bool> MigratePlaintextAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var transaction = connection.BeginTransaction();
        var paperRows = new List<(string Id, string Title, string Subject, string ExamCode, int TotalMarks,
            string Sections, string Instructions, string Content)>();
        var papers = connection.CreateCommand();
        papers.Transaction = transaction;
        papers.CommandText =
            "SELECT paper_id,title,subject,exam_code,total_marks,sections_json,instructions,content_json FROM papers " +
            "WHERE protected_payload IS NULL OR protected_payload='';";
        await using (var reader = await papers.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                paperRows.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    reader.GetInt32(4), reader.GetString(5), reader.GetString(6), reader.GetString(7)));
            }
        }

        foreach (var row in paperRows)
        {
            var sections = JsonSerializer.Deserialize<IReadOnlyList<PaperSection>>(row.Sections, JsonOptions)
                ?? throw new InvalidDataException($"Legacy sections for paper {row.Id} are invalid.");
            var content = JsonSerializer.Deserialize<PaperDocument>(row.Content, JsonOptions)
                ?? throw new InvalidDataException($"Legacy content for paper {row.Id} is invalid.");
            var payload = new ProtectedPaperPayload(row.Title, row.Subject, row.ExamCode, sections, row.TotalMarks, row.Instructions, content);
            var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText =
                "UPDATE papers SET protected_payload=$payload,sections_json='[]',instructions='',content_json='' " +
                "WHERE paper_id=$id;";
            update.Parameters.AddWithValue("$payload", Protect(payload));
            update.Parameters.AddWithValue("$id", row.Id);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        var versionRows = new List<(string PaperId, int Version, string Snapshot)>();
        var versions = connection.CreateCommand();
        versions.Transaction = transaction;
        versions.CommandText =
            "SELECT paper_id,version,snapshot_json FROM paper_versions " +
            "WHERE protected_snapshot IS NULL OR protected_snapshot='';";
        await using (var reader = await versions.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                versionRows.Add((reader.GetString(0), reader.GetInt32(1), reader.GetString(2)));
            }
        }

        foreach (var row in versionRows)
        {
            var snapshot = JsonSerializer.Deserialize<PaperSummary>(row.Snapshot, JsonOptions)
                ?? throw new InvalidDataException($"Legacy version {row.Version} for paper {row.PaperId} is invalid.");
            var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText =
                "UPDATE paper_versions SET protected_snapshot=$snapshot,snapshot_json='' " +
                "WHERE paper_id=$paper AND version=$version;";
            update.Parameters.AddWithValue("$snapshot", _paperProtector.Protect(JsonSerializer.Serialize(snapshot, JsonOptions)));
            update.Parameters.AddWithValue("$paper", row.PaperId);
            update.Parameters.AddWithValue("$version", row.Version);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return paperRows.Count > 0 || versionRows.Count > 0;
    }

    private string Protect<T>(T value) =>
        _paperProtector.Protect(JsonSerializer.Serialize(value, JsonOptions));

    private T Unprotect<T>(string protectedValue)
    {
        try
        {
            var value = _paperProtector.Unprotect(protectedValue);
            return JsonSerializer.Deserialize<T>(value, JsonOptions)
                ?? throw new PaperIntegrityException("The encrypted paper payload is invalid.");
        }
        catch (CryptographicException exception)
        {
            throw new PaperIntegrityException("Paper integrity verification failed. The document cannot be opened.", exception);
        }
        catch (JsonException exception)
        {
            throw new PaperIntegrityException("Paper integrity verification failed. The document cannot be opened.", exception);
        }
    }

    private async Task RecordVersionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        PaperSummary paper,
        string userId,
        string action,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "INSERT INTO paper_versions(paper_id,version,action,changed_by,changed_at,snapshot_json,protected_snapshot) " +
            "VALUES($paper,$version,$action,$user,$changed,'',$snapshot);";
        command.Parameters.AddWithValue("$paper", paper.PaperId);
        command.Parameters.AddWithValue("$version", paper.Version);
        command.Parameters.AddWithValue("$action", action);
        command.Parameters.AddWithValue("$user", userId);
        command.Parameters.AddWithValue("$changed", now.ToString("O"));
        command.Parameters.AddWithValue("$snapshot", _paperProtector.Protect(JsonSerializer.Serialize(paper, JsonOptions)));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private void AddPaperParameters(SqliteCommand command, PaperSummary paper)
    {
        command.Parameters.AddWithValue("$id", paper.PaperId);
        command.Parameters.AddWithValue("$owner", paper.OwnerId);
        command.Parameters.AddWithValue("$title", paper.Title);
        command.Parameters.AddWithValue("$subject", paper.Subject);
        command.Parameters.AddWithValue("$code", paper.ExamCode);
        command.Parameters.AddWithValue("$marks", paper.TotalMarks);
        var payload = ToPayload(paper);
        command.Parameters.AddWithValue("$protected", _paperProtector.Protect(JsonSerializer.Serialize(payload, JsonOptions)));
        command.Parameters.AddWithValue("$version", paper.Version);
        command.Parameters.AddWithValue("$created", paper.CreatedAt.ToString("O"));
        command.Parameters.AddWithValue("$updated", paper.UpdatedAt.ToString("O"));
    }

    private static ProtectedPaperPayload ToPayload(PaperSummary paper) =>
        new(paper.Title, paper.Subject, paper.ExamCode, paper.Sections, paper.TotalMarks, paper.Instructions, paper.Content);

    private static bool CanEdit(PaperSummary paper, string userId, string role) =>
        paper.Status is "draft" or "changes_requested" &&
        (role == "admin" || (role == "setter" && paper.OwnerId == userId));

    private static void Validate(PaperDraftRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Title) || request.Title.Trim().Length > 160 ||
            string.IsNullOrWhiteSpace(request.Subject) || request.Subject.Trim().Length > 120 ||
            string.IsNullOrWhiteSpace(request.ExamCode) || request.ExamCode.Trim().Length > 64)
        {
            throw new ArgumentException("Title, subject, and exam code are required and must fit their length limits.");
        }

        if (request.Sections is null || request.Content is null || request.Instructions is null ||
            request.Content.Paragraphs is null)
        {
            throw new ArgumentException("Paper sections, instructions, and rich-text content are required.");
        }

        if (request.TotalMarks is < 1 or > 10000 ||
            request.Sections.Count is < 1 or > 30 ||
            request.Sections.Any(section => section is null || string.IsNullOrWhiteSpace(section.Name) ||
                section.Name.Trim().Length > 80 || section.Marks < 1) ||
            request.Sections.Sum(section => (long)section.Marks) != request.TotalMarks)
        {
            throw new ArgumentException("Add valid sections whose marks add up to the paper's total marks.");
        }

        if (request.Instructions.Length > 4000 || request.Content.Paragraphs.Count is < 1 or > 2000 ||
            request.Content.Paragraphs.Any(paragraph => paragraph is null || paragraph.Runs is null ||
                paragraph.Runs.Count is < 1 or > 200 || paragraph.Runs.Any(run => run is null || run.Text is null)) ||
            request.Content.Paragraphs.SelectMany(paragraph => paragraph.Runs).Any(run => run.Text.Length > 10000) ||
            request.Content.Paragraphs.SelectMany(paragraph => paragraph.Runs).Sum(run => (long)run.Text.Length) > 500000)
        {
            throw new ArgumentException("Paper instructions or rich-text content exceeds the allowed limits.");
        }
    }

    private static async Task<string> GetDisplayNameAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string userId,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT display_name FROM users WHERE user_id=$user;";
        command.Parameters.AddWithValue("$user", userId);
        return (string?)await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Paper owner is unavailable.");
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}

internal sealed class PaperIntegrityException : Exception
{
    public PaperIntegrityException(string message) : base(message)
    {
    }

    public PaperIntegrityException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
