namespace SecureExam.Api.Models;

public sealed record LoginRequest(string Email, string Password, string? DeviceId = null);
public sealed record WorkstationPolicyReport(
    string OperatingSystem,
    bool Windows,
    bool ApplicationControlPolicyDetected,
    bool SystemRestrictionsConfigured);
public sealed record WorkstationAssignmentRequest(string Centre, string Room, string WorkstationId);
public sealed record MfaRequest(
    string ChallengeId,
    string Code,
    string DeviceId,
    string DeviceName,
    string DeviceSecret,
    WorkstationPolicyReport WorkstationPolicy);
public sealed record MfaSetupRequest(
    string ChallengeId,
    string Code,
    string DeviceId,
    string DeviceName,
    string DeviceSecret,
    WorkstationPolicyReport WorkstationPolicy);
public sealed record CreateUserRequest(string Email, string DisplayName, string Role, string Password);
public sealed record DeviceStatusRequest(string Status);
public sealed record RoleRequest(string Role);
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record UserSummary(
    string UserId,
    string DisplayName,
    string Email,
    string Role,
    string Status,
    bool MfaEnabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastLoginAt);

public sealed record DeviceSummary(
    string DeviceId,
    string UserId,
    string UserName,
    string Name,
    string Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt,
    string Centre,
    string Room,
    string WorkstationId,
    string ComplianceStatus,
    string OperatingSystem,
    bool ApplicationControlPolicyDetected,
    bool SystemRestrictionsConfigured,
    DateTimeOffset? ComplianceCheckedAt);

public sealed record SessionIdentity(
    string SessionId,
    string UserId,
    string DeviceId,
    DateTimeOffset ExpiresAt,
    string DisplayName,
    string Email,
    string Role,
    bool MfaEnabled);

public sealed record LoginChallenge(string ChallengeId, bool NeedsMfaSetup, string? Secret, string? ProvisioningUri);
public sealed record LoginResult(string State, UserSummary? User, DateTimeOffset? ExpiresAt, string? Message);
public sealed record MfaSetupResult(string State, UserSummary? User, DateTimeOffset? ExpiresAt, string? Message);
