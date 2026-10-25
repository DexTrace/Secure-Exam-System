using System.Net.Http;
using System.Text.Json;
using SecureExam.Desktop.Models;

namespace SecureExam.Desktop.Services;

internal sealed partial class ApiClient
{
    public async Task<InvestigationEvidenceReport> SearchInvestigationAsync(
        string type,
        string query,
        CancellationToken cancellationToken = default)
    {
        var endpoint = $"api/investigations/search?type={Uri.EscapeDataString(type)}&query={Uri.EscapeDataString(query)}";
        var body = await SendAsync(HttpMethod.Get, endpoint, null, cancellationToken);
        return ReadProperty<InvestigationEvidenceReport>(body, "report");
    }

    public async Task<InvestigationIncident> CreateInvestigationIncidentAsync(
        CreateInvestigationIncidentRequest request,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(
            HttpMethod.Post, "api/investigations/incidents", request, cancellationToken);
        return ReadProperty<InvestigationIncident>(body, "incident");
    }
}
