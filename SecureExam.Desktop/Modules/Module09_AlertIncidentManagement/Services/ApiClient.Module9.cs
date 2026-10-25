using System.Net.Http;
using SecureExam.Desktop.Models;

namespace SecureExam.Desktop.Services;

internal sealed partial class ApiClient
{
    public async Task<AlertDashboardData> GetAlertsAsync(
        string? status,
        CancellationToken cancellationToken = default)
    {
        var query = status is null ? string.Empty : $"?status={Uri.EscapeDataString(status)}";
        var body = await SendAsync(HttpMethod.Get, $"api/alerts{query}", null, cancellationToken);
        return new AlertDashboardData(
            ReadList<SecurityAlert>(body, "alerts"),
            ReadList<AlertCase>(body, "cases"));
    }

    public async Task<SecurityAlert> ReviewAlertAsync(
        string alertId,
        string? note,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(
            HttpMethod.Post,
            $"api/alerts/{Uri.EscapeDataString(alertId)}/review",
            new AlertActionRequest(note),
            cancellationToken);
        return ReadProperty<SecurityAlert>(body, "alert");
    }

    public async Task<SecurityAlert> ResolveAlertAsync(
        string alertId,
        string note,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(
            HttpMethod.Post,
            $"api/alerts/{Uri.EscapeDataString(alertId)}/resolve",
            new AlertActionRequest(note),
            cancellationToken);
        return ReadProperty<SecurityAlert>(body, "alert");
    }

    public async Task<AlertCase> CreateAlertCaseAsync(
        string alertId,
        string summary,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(
            HttpMethod.Post,
            $"api/alerts/{Uri.EscapeDataString(alertId)}/cases",
            new CreateAlertCaseRequest(summary),
            cancellationToken);
        return ReadProperty<AlertCase>(body, "incidentCase");
    }
}
