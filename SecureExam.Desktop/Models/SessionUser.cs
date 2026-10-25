using System.Text.Json.Serialization;

namespace SecureExam.Desktop.Models;

public sealed class SessionUser
{
    [JsonPropertyName("userId")]
    public string UserId { get; init; } = string.Empty;

    [JsonPropertyName("displayName")]
    public string DisplayName { get; init; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("role")]
    public string Role { get; init; } = string.Empty;

    [JsonPropertyName("mfaEnabled")]
    public bool MfaEnabled { get; init; }
}
