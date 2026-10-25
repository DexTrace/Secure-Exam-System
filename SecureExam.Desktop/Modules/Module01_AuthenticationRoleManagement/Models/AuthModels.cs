using System.Text.Json.Serialization;

namespace SecureExam.Desktop.Models;

public sealed class LoginChallenge
{
    [JsonPropertyName("challengeId")]
    public string ChallengeId { get; init; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; init; } = string.Empty;

    [JsonPropertyName("secret")]
    public string? Secret { get; init; }

    [JsonPropertyName("provisioningUri")]
    public string? ProvisioningUri { get; init; }

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}

public sealed class LoginResult
{
    [JsonPropertyName("state")]
    public string State { get; init; } = string.Empty;

    [JsonPropertyName("user")]
    public SessionUser? User { get; init; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }
}

public sealed class UserSummary
{
    [JsonPropertyName("userId")] public string UserId { get; init; } = string.Empty;
    [JsonPropertyName("displayName")] public string DisplayName { get; init; } = string.Empty;
    [JsonPropertyName("email")] public string Email { get; init; } = string.Empty;
    [JsonPropertyName("role")] public string Role { get; init; } = string.Empty;
    [JsonPropertyName("status")] public string Status { get; init; } = string.Empty;
    [JsonPropertyName("mfaEnabled")] public bool MfaEnabled { get; init; }
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; init; }
    [JsonPropertyName("lastLoginAt")] public DateTimeOffset? LastLoginAt { get; init; }
}

public sealed class DeviceSummary
{
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = string.Empty;
    [JsonPropertyName("userId")] public string UserId { get; init; } = string.Empty;
    [JsonPropertyName("userName")] public string UserName { get; init; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("status")] public string Status { get; init; } = string.Empty;
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; init; }
    [JsonPropertyName("lastSeenAt")] public DateTimeOffset? LastSeenAt { get; init; }
    [JsonPropertyName("centre")] public string Centre { get; init; } = string.Empty;
    [JsonPropertyName("room")] public string Room { get; init; } = string.Empty;
    [JsonPropertyName("workstationId")] public string WorkstationId { get; init; } = string.Empty;
    [JsonPropertyName("complianceStatus")] public string ComplianceStatus { get; init; } = "unknown";
    [JsonPropertyName("operatingSystem")] public string OperatingSystem { get; init; } = string.Empty;
    [JsonPropertyName("applicationControlPolicyDetected")] public bool ApplicationControlPolicyDetected { get; init; }
    [JsonPropertyName("systemRestrictionsConfigured")] public bool SystemRestrictionsConfigured { get; init; }
    [JsonPropertyName("complianceCheckedAt")] public DateTimeOffset? ComplianceCheckedAt { get; init; }
}

public sealed class WorkstationPolicyReport
{
    [JsonPropertyName("operatingSystem")] public string OperatingSystem { get; init; } = string.Empty;
    [JsonPropertyName("windows")] public bool Windows { get; init; }
    [JsonPropertyName("applicationControlPolicyDetected")] public bool ApplicationControlPolicyDetected { get; init; }
    [JsonPropertyName("systemRestrictionsConfigured")] public bool SystemRestrictionsConfigured { get; init; }
}

public sealed class AuditEvent
{
    [JsonPropertyName("sequence")] public long Sequence { get; init; }
    [JsonPropertyName("eventId")] public string EventId { get; init; } = string.Empty;
    [JsonPropertyName("serverTimestamp")] public DateTimeOffset ServerTimestamp { get; init; }
    [JsonPropertyName("eventType")] public string EventType { get; init; } = string.Empty;
    [JsonPropertyName("userId")] public string? UserId { get; init; }
    [JsonPropertyName("workstationId")] public string? WorkstationId { get; init; }
    [JsonPropertyName("resourceType")] public string? ResourceType { get; init; }
    [JsonPropertyName("resourceId")] public string? ResourceId { get; init; }
    [JsonPropertyName("outcome")] public string Outcome { get; init; } = string.Empty;
    [JsonPropertyName("details")] public string Details { get; init; } = string.Empty;
    [JsonPropertyName("previousHash")] public string PreviousHash { get; init; } = string.Empty;
    [JsonPropertyName("eventHash")] public string EventHash { get; init; } = string.Empty;
}

public sealed class AuditVerificationResult
{
    [JsonPropertyName("valid")] public bool Valid { get; init; }
    [JsonPropertyName("checkedEvents")] public long CheckedEvents { get; init; }
    [JsonPropertyName("firstInvalidSequence")] public long? FirstInvalidSequence { get; init; }
    [JsonPropertyName("message")] public string Message { get; init; } = string.Empty;
}

public sealed class CurrentSession
{
    [JsonPropertyName("user")] public SessionUser User { get; init; } = new();
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = string.Empty;
    [JsonPropertyName("expiresAt")] public DateTimeOffset ExpiresAt { get; init; }
}
