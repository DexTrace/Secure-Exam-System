namespace SecureExam.Desktop.Models;

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
