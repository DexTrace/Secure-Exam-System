using Microsoft.Data.Sqlite;
using SecureExam.Api.Models;

namespace SecureExam.Api.Data;

internal sealed class DocumentFingerprintStore
{
    private readonly string _connectionString;
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private bool _initialized;

    public DocumentFingerprintStore(IConfiguration configuration)
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

    public async Task RecordAsync(
        string copyId,
        PaperSummary paper,
        string recipientUserId,
        string recipientName,
        string recipientEmail,
        string contentSha256,
        string pdfSha256,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "INSERT INTO document_fingerprints(copy_id,paper_id,paper_version,recipient_user_id,recipient_name," +
            "recipient_email,content_sha256,pdf_sha256,issued_at) " +
            "SELECT $copy,$paper,$version,$recipient,$name,$email,$content,$pdf,$issued " +
            "WHERE EXISTS(SELECT 1 FROM issued_paper_copies c WHERE c.copy_id=$copy AND c.paper_id=$paper " +
            "AND c.recipient_user_id=$recipient AND c.action='export' AND c.content_sha256=$content);";
        command.Parameters.AddWithValue("$copy", copyId);
        command.Parameters.AddWithValue("$paper", paper.PaperId);
        command.Parameters.AddWithValue("$version", paper.Version);
        command.Parameters.AddWithValue("$recipient", recipientUserId);
        command.Parameters.AddWithValue("$name", recipientName);
        command.Parameters.AddWithValue("$email", recipientEmail);
        command.Parameters.AddWithValue("$content", contentSha256);
        command.Parameters.AddWithValue("$pdf", pdfSha256);
        command.Parameters.AddWithValue("$issued", issuedAt.ToUniversalTime().ToString("O"));
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("The PDF could not be linked to its issued-copy record.");
        }
    }

    public async Task<DocumentFingerprintMatch?> FindAsync(
        string pdfSha256,
        CancellationToken cancellationToken)
    {
        await EnsureInitializedAsync(cancellationToken);
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT f.copy_id,f.paper_id,p.title,f.paper_version,f.recipient_user_id,f.recipient_name," +
            "f.recipient_email,f.issued_at,f.pdf_sha256 FROM document_fingerprints f " +
            "JOIN issued_paper_copies c ON c.copy_id=f.copy_id " +
            "JOIN papers p ON p.paper_id=f.paper_id WHERE f.pdf_sha256=$hash LIMIT 1;";
        command.Parameters.AddWithValue("$hash", pdfSha256);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new DocumentFingerprintMatch(
            true,
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetInt32(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.GetString(6),
            DateTimeOffset.Parse(reader.GetString(7)),
            reader.GetString(8));
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
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
                "CREATE TABLE IF NOT EXISTS document_fingerprints(" +
                "copy_id TEXT PRIMARY KEY,paper_id TEXT NOT NULL,paper_version INTEGER NOT NULL," +
                "recipient_user_id TEXT NOT NULL,recipient_name TEXT NOT NULL,recipient_email TEXT NOT NULL," +
                "content_sha256 TEXT NOT NULL,pdf_sha256 TEXT NOT NULL UNIQUE,issued_at TEXT NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_document_fingerprints_pdf ON document_fingerprints(pdf_sha256);" +
                "CREATE TRIGGER IF NOT EXISTS document_fingerprints_no_update BEFORE UPDATE ON document_fingerprints " +
                "BEGIN SELECT RAISE(ABORT,'document fingerprints are append-only'); END;" +
                "CREATE TRIGGER IF NOT EXISTS document_fingerprints_no_delete BEFORE DELETE ON document_fingerprints " +
                "BEGIN SELECT RAISE(ABORT,'document fingerprints are append-only'); END;";
            await command.ExecuteNonQueryAsync(cancellationToken);
            _initialized = true;
        }
        finally
        {
            _initializeLock.Release();
        }
    }
}
