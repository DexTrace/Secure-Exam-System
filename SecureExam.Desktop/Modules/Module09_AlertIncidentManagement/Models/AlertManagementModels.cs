using System.Text.Json.Serialization;

namespace SecureExam.Desktop.Models;

internal sealed record SecurityAlert(
    [property: JsonPropertyName("alertId")] string AlertId,
    [property: JsonPropertyName("alertType")] string AlertType,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("details")] string Details,
    [property: JsonPropertyName("actorUserId")] string? ActorUserId,
    [property: JsonPropertyName("workstationId")] string? WorkstationId,
    [property: JsonPropertyName("resourceType")] string? ResourceType,
    [property: JsonPropertyName("resourceId")] string? ResourceId,
    [property: JsonPropertyName("createdAt")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("reviewedBy")] string? ReviewedBy,
    [property: JsonPropertyName("reviewedByName")] string? ReviewedByName,
    [property: JsonPropertyName("reviewedAt")] DateTimeOffset? ReviewedAt,
    [property: JsonPropertyName("resolvedBy")] string? ResolvedBy,
    [property: JsonPropertyName("resolvedByName")] string? ResolvedByName,
    [property: JsonPropertyName("resolvedAt")] DateTimeOffset? ResolvedAt,
    [property: JsonPropertyName("reviewNote")] string? ReviewNote);

internal sealed record AlertActionRequest(
    [property: JsonPropertyName("note")] string? Note);

internal sealed record CreateAlertCaseRequest(
    [property: JsonPropertyName("summary")] string Summary);

internal sealed record AlertCase(
    [property: JsonPropertyName("caseId")] string CaseId,
    [property: JsonPropertyName("alertId")] string AlertId,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("createdBy")] string CreatedBy,
    [property: JsonPropertyName("createdByName")] string CreatedByName,
    [property: JsonPropertyName("createdAt")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("status")] string Status);

internal sealed record AlertDashboardData(
    IReadOnlyList<SecurityAlert> Alerts,
    IReadOnlyList<AlertCase> Cases);
