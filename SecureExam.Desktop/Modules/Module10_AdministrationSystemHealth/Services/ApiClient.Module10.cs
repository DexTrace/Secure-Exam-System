using System.Net.Http;
using SecureExam.Desktop.Models;

namespace SecureExam.Desktop.Services;

internal sealed partial class ApiClient
{
    public async Task<SystemHealthSnapshot> GetSystemHealthAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/admin/system", null, cancellationToken);
        return ReadProperty<SystemHealthSnapshot>(body, "system");
    }

    public async Task<SystemBackupRecord> CreateSystemBackupAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Post, "api/admin/system/backups", new { }, cancellationToken);
        return ReadProperty<SystemBackupRecord>(body, "backup");
    }
}
