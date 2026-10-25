using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using SecureExam.Desktop.Models;

namespace SecureExam.Desktop.Services;

internal sealed partial class ApiClient : IDisposable
{
    private readonly CookieContainer _cookies = new();
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public ApiClient()
    {
        var configuredUrl = Environment.GetEnvironmentVariable("SECURE_EXAM_API_URL");
        var baseAddress = string.IsNullOrWhiteSpace(configuredUrl)
            ? "http://127.0.0.1:5188/"
            : configuredUrl.TrimEnd('/') + "/";
        var apiAddress = new Uri(baseAddress, UriKind.Absolute);
        if (apiAddress.Scheme != Uri.UriSchemeHttps &&
            (apiAddress.Scheme != Uri.UriSchemeHttp || !apiAddress.IsLoopback))
        {
            throw new InvalidOperationException("Remote authentication services must use HTTPS.");
        }

        _http = new HttpClient(new HttpClientHandler
        {
            CookieContainer = _cookies,
            UseCookies = true
        })
        {
            BaseAddress = apiAddress,
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    public async Task<LoginChallenge> LoginAsync(
        string email,
        string password,
        DeviceIdentity device,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Post, "api/auth/login",
            new { email, password, deviceId = device.DeviceId }, cancellationToken);
        return Deserialize<LoginChallenge>(body);
    }

    public async Task<LoginResult> CompleteMfaAsync(
        string challengeId,
        string code,
        DeviceIdentity device,
        bool setup,
        CancellationToken cancellationToken = default)
    {
        var endpoint = setup ? "api/auth/mfa/setup" : "api/auth/mfa/verify";
        var workstationPolicy = WorkstationPolicyInspector.Inspect();
        var payload = new
        {
            challengeId,
            code,
            deviceId = device.DeviceId,
            deviceName = device.Name,
            deviceSecret = device.Secret,
            workstationPolicy
        };
        var body = await SendAsync(HttpMethod.Post, endpoint, payload, cancellationToken);
        return Deserialize<LoginResult>(body);
    }

    public async Task<CurrentSession> GetCurrentSessionAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/auth/me", null, cancellationToken);
        return Deserialize<CurrentSession>(body);
    }

    public async Task<IReadOnlyList<UserSummary>> GetUsersAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/auth/users", null, cancellationToken);
        return ReadList<UserSummary>(body, "users");
    }

    public async Task<IReadOnlyList<DeviceSummary>> GetDevicesAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/auth/devices", null, cancellationToken);
        return ReadList<DeviceSummary>(body, "devices");
    }

    public async Task<IReadOnlyList<AuditEvent>> GetAuditEventsAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/audit/events?limit=200", null, cancellationToken);
        return ReadList<AuditEvent>(body, "events");
    }

    public async Task<AuditVerificationResult> VerifyAuditChainAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/audit/verify", null, cancellationToken);
        return ReadProperty<AuditVerificationResult>(body, "verification");
    }

    public async Task<IReadOnlyList<PaperSummary>> GetPapersAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/papers", null, cancellationToken);
        return ReadList<PaperSummary>(body, "papers");
    }

    public async Task<IReadOnlyList<DistributionGrant>> GetDistributionGrantsAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/papers/distribution-grants", null, cancellationToken);
        return ReadList<DistributionGrant>(body, "grants");
    }

    public async Task<IReadOnlyList<IssuedPaperCopy>> GetIssuedCopiesAsync(CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/papers/issued-copies?limit=200", null, cancellationToken);
        return ReadList<IssuedPaperCopy>(body, "copies");
    }

    public async Task<DistributionGrant> CreateDistributionGrantAsync(
        string paperId,
        string recipientUserId,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Post, "api/papers/distribution-grants",
            new { paperId, recipientUserId, expiresAt }, cancellationToken);
        return ReadProperty<DistributionGrant>(body, "grant");
    }

    public Task RevokeDistributionGrantAsync(string grantId, CancellationToken cancellationToken = default) =>
        SendAsync(new HttpMethod("PATCH"),
            $"api/papers/distribution-grants/{Uri.EscapeDataString(grantId)}/revoke",
            new { }, cancellationToken);

    public async Task<PaperSummary> GetPaperAsync(string paperId, CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get,
            $"api/papers/{Uri.EscapeDataString(paperId)}", null, cancellationToken);
        return ReadProperty<PaperSummary>(body, "paper");
    }

    public async Task<PaperSummary> CreatePaperAsync(
        PaperDraftRequest request,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Post, "api/papers", request, cancellationToken);
        return ReadProperty<PaperSummary>(body, "paper");
    }

    public async Task<PaperSummary> SavePaperAsync(
        string paperId,
        PaperDraftRequest request,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Put,
            $"api/papers/{Uri.EscapeDataString(paperId)}", request, cancellationToken);
        return ReadProperty<PaperSummary>(body, "paper");
    }

    public async Task<IReadOnlyList<PaperVersion>> GetPaperVersionsAsync(
        string paperId,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get,
            $"api/papers/{Uri.EscapeDataString(paperId)}/versions", null, cancellationToken);
        return ReadList<PaperVersion>(body, "versions");
    }

    public async Task<PaperAccessResult> AuthorizePaperAccessAsync(
        string paperId,
        string action,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Post,
            $"api/papers/{Uri.EscapeDataString(paperId)}/{action}", new { }, cancellationToken);
        return Deserialize<PaperAccessResult>(body);
    }

    public async Task<IReadOnlyList<PaperAccessEvent>> GetPaperAccessEventsAsync(
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Get, "api/papers/access-events", null, cancellationToken);
        return ReadList<PaperAccessEvent>(body, "events");
    }

    public async Task<PaperSummary> TransitionPaperAsync(
        string paperId,
        string action,
        string? comment = null,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Post,
            $"api/papers/{Uri.EscapeDataString(paperId)}/transition",
            new { action, comment }, cancellationToken);
        return ReadProperty<PaperSummary>(body, "paper");
    }

    public async Task<UserSummary> CreateUserAsync(
        string email,
        string displayName,
        string role,
        string temporaryPassword,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(HttpMethod.Post, "api/auth/users",
            new { email, displayName, role, password = temporaryPassword }, cancellationToken);
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("user").Deserialize<UserSummary>(JsonOptions)
            ?? throw new ApiRequestException("The server returned an invalid user.");
    }

    public async Task<UserSummary> SetUserStatusAsync(
        string userId,
        string status,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(new HttpMethod("PATCH"),
            $"api/auth/users/{Uri.EscapeDataString(userId)}/status",
            new { status }, cancellationToken);
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("user").Deserialize<UserSummary>(JsonOptions)
            ?? throw new ApiRequestException("The server returned an invalid user.");
    }

    public async Task<UserSummary> SetUserRoleAsync(
        string userId,
        string role,
        CancellationToken cancellationToken = default)
    {
        var body = await SendAsync(new HttpMethod("PATCH"),
            $"api/auth/users/{Uri.EscapeDataString(userId)}/role",
            new { role }, cancellationToken);
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("user").Deserialize<UserSummary>(JsonOptions)
            ?? throw new ApiRequestException("The server returned an invalid user.");
    }

    public Task ChangePasswordAsync(
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default) =>
        SendAsync(HttpMethod.Post, "api/auth/change-password",
            new { currentPassword, newPassword }, cancellationToken);

    public Task ResetMfaAsync(string userId, CancellationToken cancellationToken = default) =>
        SendAsync(HttpMethod.Post,
            $"api/auth/users/{Uri.EscapeDataString(userId)}/reset-mfa",
            new { }, cancellationToken);

    public Task SetDeviceStatusAsync(string deviceId, string status, CancellationToken cancellationToken = default) =>
        SendAsync(new HttpMethod("PATCH"),
            $"api/auth/devices/{Uri.EscapeDataString(deviceId)}/status",
            new { status }, cancellationToken);

    public Task AssignWorkstationAsync(
        string deviceId,
        string centre,
        string room,
        string workstationId,
        CancellationToken cancellationToken = default) =>
        SendAsync(HttpMethod.Put,
            $"api/auth/devices/{Uri.EscapeDataString(deviceId)}/workstation",
            new { centre, room, workstationId }, cancellationToken);

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await SendAsync(HttpMethod.Post, "api/auth/logout", new { }, cancellationToken);
        }
        finally
        {
            _cookies.GetCookies(_http.BaseAddress!).Clear();
        }
    }

    private async Task<string> SendAsync(
        HttpMethod method,
        string endpoint,
        object? payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, endpoint);
        if (payload is not null)
        {
            request.Content = JsonContent.Create(payload);
        }

        using var response = await _http.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        EnsureSuccess(response.StatusCode, body);
        return body;
    }

    private static T Deserialize<T>(string body) =>
        JsonSerializer.Deserialize<T>(body, JsonOptions)
        ?? throw new ApiRequestException("The server returned an invalid response.");

    private static T ReadProperty<T>(string body, string property)
    {
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty(property).Deserialize<T>(JsonOptions)
            ?? throw new ApiRequestException("The server returned an invalid response.");
    }

    private static IReadOnlyList<T> ReadList<T>(string body, string property)
    {
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty(property).Deserialize<List<T>>(JsonOptions)
            ?? new List<T>();
    }

    private static void EnsureSuccess(HttpStatusCode statusCode, string body)
    {
        if ((int)statusCode is >= 200 and < 300)
        {
            return;
        }

        if (statusCode == HttpStatusCode.Unauthorized)
        {
            throw new SessionExpiredException(ReadError(body, "Your session expired. Sign in again."));
        }

        if (statusCode == HttpStatusCode.Forbidden)
        {
            throw new ApiRequestException("Your account does not have permission to perform this action.");
        }

        throw new ApiRequestException(ReadError(body, $"The server returned {(int)statusCode}."));
    }

    private static string ReadError(string body, string fallback)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.TryGetProperty("error", out var error) &&
                error.ValueKind == JsonValueKind.String)
            {
                return error.GetString() ?? fallback;
            }
        }
        catch (JsonException)
        {
        }

        return fallback;
    }

    public void Dispose() => _http.Dispose();
}
