using System.Globalization;
using System.IO.Compression;
using Microsoft.Data.Sqlite;

namespace SecureExam.Api.Services;

internal sealed class SystemAdministrationService
{
    private const string BackupPrefix = "secure-exam-backup-";
    private readonly string _dataDirectory;
    private readonly string _databasePath;
    private readonly string _keyDirectory;
    private readonly string _backupDirectory;
    private readonly int _backupRetentionCount;
    private readonly bool _requireCompliantWorkstations;
    private readonly bool _protectedKeysConfigured;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;

    public SystemAdministrationService(IConfiguration configuration)
    {
        _dataDirectory = configuration["SECURE_EXAM_DATA_DIR"];
        if (string.IsNullOrWhiteSpace(_dataDirectory))
        {
            _dataDirectory = Path.Combine(AppContext.BaseDirectory, "data");
        }

        _dataDirectory = Path.GetFullPath(_dataDirectory);
        _databasePath = Path.Combine(_dataDirectory, "secure-exam-auth.db");
        _keyDirectory = Path.Combine(_dataDirectory, "keys");
        var configuredBackupDirectory = configuration["SECURE_EXAM_BACKUP_DIR"];
        _backupDirectory = Path.GetFullPath(string.IsNullOrWhiteSpace(configuredBackupDirectory)
            ? Path.Combine(_dataDirectory, "backups")
            : configuredBackupDirectory);

        var retentionSetting = configuration["SECURE_EXAM_BACKUP_RETENTION_COUNT"];
        if (string.IsNullOrWhiteSpace(retentionSetting))
        {
            _backupRetentionCount = 10;
        }
        else if (!int.TryParse(retentionSetting, NumberStyles.None, CultureInfo.InvariantCulture,
                     out _backupRetentionCount) ||
                 _backupRetentionCount is < 1 or > 100)
        {
            throw new InvalidOperationException("SECURE_EXAM_BACKUP_RETENTION_COUNT must be between 1 and 100.");
        }

        _requireCompliantWorkstations =
            bool.TryParse(configuration["SECURE_EXAM_REQUIRE_COMPLIANT_WORKSTATION"], out var requireCompliance) &&
            requireCompliance;
        _protectedKeysConfigured = !string.IsNullOrWhiteSpace(configuration["SECURE_EXAM_KEY_ENCRYPTION_CERT"]);
    }

    public async Task<SystemHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadOnly
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        var integrityCommand = connection.CreateCommand();
        integrityCommand.CommandText = "PRAGMA quick_check;";
        var integrity = (string?)await integrityCommand.ExecuteScalarAsync(cancellationToken) ?? "unknown";
        if (!string.Equals(integrity, "ok", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Database integrity check failed: {integrity}");
        }

        var counts = connection.CreateCommand();
        counts.CommandText =
            "SELECT (SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM devices);";
        await using var reader = await counts.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidDataException("System health counters could not be read.");
        }

        var userCount = reader.GetInt32(0);
        var deviceCount = reader.GetInt32(1);
        var backupRecords = GetBackups();
        var keyFiles = Directory.Exists(_keyDirectory)
            ? Directory.EnumerateFiles(_keyDirectory, "*", SearchOption.AllDirectories).Count()
            : 0;

        return new SystemHealthSnapshot(
            "healthy",
            "connected",
            typeof(SystemAdministrationService).Assembly.GetName().Version?.ToString() ?? "unknown",
            Environment.Version.ToString(),
            userCount,
            deviceCount,
            _startedAt,
            DateTimeOffset.UtcNow,
            new SecurityPolicyStatus(
                _requireCompliantWorkstations,
                _protectedKeysConfigured,
                TimeSpan.FromHours(8).TotalHours,
                "Audit records are append-only; automatic audit deletion is disabled.",
                _backupRetentionCount),
            keyFiles,
            backupRecords);
    }

    public async Task<SystemBackupRecord> CreateBackupAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_backupDirectory);
        var backupId = DateTimeOffset.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture)
                       + "-" + Guid.NewGuid().ToString("N");
        var workDirectory = Path.Combine(_backupDirectory, ".working-" + Guid.NewGuid().ToString("N"));
        var temporaryArchive = Path.Combine(_backupDirectory, "." + BackupPrefix + backupId + ".tmp");
        var finalArchive = Path.Combine(_backupDirectory, BackupPrefix + backupId + ".zip");
        Directory.CreateDirectory(workDirectory);
        try
        {
            var databaseBackup = Path.Combine(workDirectory, "secure-exam-auth.db");
            await using (var source = new SqliteConnection(new SqliteConnectionStringBuilder
                         {
                             DataSource = _databasePath,
                             Mode = SqliteOpenMode.ReadOnly
                         }.ToString()))
            await using (var destination = new SqliteConnection(new SqliteConnectionStringBuilder
                         {
                             DataSource = databaseBackup,
                             Mode = SqliteOpenMode.ReadWriteCreate
                         }.ToString()))
            {
                await source.OpenAsync(cancellationToken);
                await destination.OpenAsync(cancellationToken);
                source.BackupDatabase(destination);
            }

            using (var archive = ZipFile.Open(temporaryArchive, ZipArchiveMode.Create))
            {
                archive.CreateEntryFromFile(databaseBackup, "secure-exam-auth.db", CompressionLevel.Optimal);
                if (Directory.Exists(_keyDirectory))
                {
                    foreach (var keyFile in Directory.EnumerateFiles(_keyDirectory, "*", SearchOption.AllDirectories))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var relativePath = Path.GetRelativePath(_keyDirectory, keyFile);
                        archive.CreateEntryFromFile(
                            keyFile,
                            Path.Combine("keys", relativePath).Replace(Path.DirectorySeparatorChar, '/'),
                            CompressionLevel.Optimal);
                    }
                }

                var manifest = archive.CreateEntry("BACKUP-README.txt", CompressionLevel.Optimal);
                await using var manifestWriter = new StreamWriter(manifest.Open());
                await manifestWriter.WriteAsync(
                    "Secure Exam System recovery backup.\n" +
                    "Contains the SQLite database and its Data Protection key ring.\n" +
                    "Treat this file as highly sensitive and restrict it to authorized administrators.\n" +
                    "Restore only while the API is stopped. Restore the database and the complete keys directory together.\n" +
                    "The configured Data Protection certificate private key may also be required to decrypt the key ring.\n");
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryArchive, finalArchive);
            PruneBackups();
            var info = new FileInfo(finalArchive);
            return new SystemBackupRecord(info.Name, info.Length, info.LastWriteTimeUtc);
        }
        finally
        {
            if (File.Exists(temporaryArchive))
            {
                File.Delete(temporaryArchive);
            }

            if (Directory.Exists(workDirectory))
            {
                Directory.Delete(workDirectory, recursive: true);
            }
        }
    }

    private IReadOnlyList<SystemBackupRecord> GetBackups()
    {
        if (!Directory.Exists(_backupDirectory))
        {
            return Array.Empty<SystemBackupRecord>();
        }

        return Directory.EnumerateFiles(_backupDirectory, BackupPrefix + "*.zip", SearchOption.TopDirectoryOnly)
            .Select(path => new FileInfo(path))
            .OrderByDescending(info => info.LastWriteTimeUtc)
            .Take(100)
            .Select(info => new SystemBackupRecord(info.Name, info.Length, info.LastWriteTimeUtc))
            .ToArray();
    }

    private void PruneBackups()
    {
        var oldBackups = Directory.EnumerateFiles(
                _backupDirectory, BackupPrefix + "*.zip", SearchOption.TopDirectoryOnly)
            .Select(path => new FileInfo(path))
            .OrderByDescending(info => info.LastWriteTimeUtc)
            .Skip(_backupRetentionCount);
        foreach (var backup in oldBackups)
        {
            backup.Delete();
        }
    }
}

internal sealed record SystemHealthSnapshot(
    string ApiStatus,
    string DatabaseStatus,
    string ApiVersion,
    string RuntimeVersion,
    int UserCount,
    int RegisteredDeviceCount,
    DateTimeOffset StartedAt,
    DateTimeOffset CheckedAt,
    SecurityPolicyStatus Policies,
    int DataProtectionKeyCount,
    IReadOnlyList<SystemBackupRecord> Backups);

internal sealed record SecurityPolicyStatus(
    bool RequireCompliantWorkstations,
    bool ProtectedKeysConfigured,
    double SessionLifetimeHours,
    string AuditRetention,
    int BackupRetentionCount);

internal sealed record SystemBackupRecord(string FileName, long SizeBytes, DateTimeOffset CreatedAt);
