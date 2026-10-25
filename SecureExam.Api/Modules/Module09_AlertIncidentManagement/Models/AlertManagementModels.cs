namespace SecureExam.Api.Models;

public sealed record SecurityAlert(
    string AlertId,
    string AlertType,
    string Severity,
    string Summary,
    string Details,
    string? ActorUserId,
    string? WorkstationId,
    string? ResourceType,
    string? ResourceId,
    DateTimeOffset CreatedAt,
    string Status,
    string? ReviewedBy,
    string? ReviewedByName,
    DateTimeOffset? ReviewedAt,
    string? ResolvedBy,
    string? ResolvedByName,
    DateTimeOffset? ResolvedAt,
    string? ReviewNote);

public sealed record AlertActionRequest(string? Note);

public sealed record CreateAlertCaseRequest(string Summary);

public sealed record AlertCase(
    string CaseId,
    string AlertId,
    string Summary,
    string CreatedBy,
    string CreatedByName,
    DateTimeOffset CreatedAt,
    string Status);
