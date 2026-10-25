using System.Text.Json.Serialization;

namespace SecureExam.Desktop.Models;

internal sealed record CreateInvestigationIncidentRequest(string Summary, string? PaperId, string? CopyId);

internal sealed record InvestigationIncident(
    [property: JsonPropertyName("incidentId")] string IncidentId,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("paperId")] string? PaperId,
    [property: JsonPropertyName("copyId")] string? CopyId,
    [property: JsonPropertyName("createdBy")] string CreatedBy,
    [property: JsonPropertyName("createdByName")] string CreatedByName,
    [property: JsonPropertyName("createdAt")] DateTimeOffset CreatedAt);

internal sealed record InvestigationAuditEntry(
    [property: JsonPropertyName("sequence")] long Sequence,
    [property: JsonPropertyName("eventId")] string EventId,
    [property: JsonPropertyName("serverTimestamp")] DateTimeOffset ServerTimestamp,
    [property: JsonPropertyName("eventType")] string EventType,
    [property: JsonPropertyName("userId")] string? UserId,
    [property: JsonPropertyName("workstationId")] string? WorkstationId,
    [property: JsonPropertyName("workstationName")] string? WorkstationName,
    [property: JsonPropertyName("centre")] string? Centre,
    [property: JsonPropertyName("room")] string? Room,
    [property: JsonPropertyName("assignedWorkstationId")] string? AssignedWorkstationId,
    [property: JsonPropertyName("resourceType")] string? ResourceType,
    [property: JsonPropertyName("resourceId")] string? ResourceId,
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("details")] string Details,
    [property: JsonPropertyName("eventHash")] string EventHash);

internal sealed record InvestigationCopyEvidence(
    [property: JsonPropertyName("copyId")] string CopyId,
    [property: JsonPropertyName("paperId")] string PaperId,
    [property: JsonPropertyName("paperTitle")] string PaperTitle,
    [property: JsonPropertyName("paperVersion")] int? PaperVersion,
    [property: JsonPropertyName("recipientUserId")] string RecipientUserId,
    [property: JsonPropertyName("recipientName")] string? RecipientName,
    [property: JsonPropertyName("recipientEmail")] string? RecipientEmail,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("issuedAt")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("contentSha256")] string ContentSha256,
    [property: JsonPropertyName("pdfSha256")] string? PdfSha256);

internal sealed record InvestigationEvidenceReport(
    [property: JsonPropertyName("searchType")] string SearchType,
    [property: JsonPropertyName("searchValue")] string SearchValue,
    [property: JsonPropertyName("generatedAt")] DateTimeOffset GeneratedAt,
    [property: JsonPropertyName("paperId")] string? PaperId,
    [property: JsonPropertyName("paperTitle")] string? PaperTitle,
    [property: JsonPropertyName("currentPaperVersion")] int? CurrentPaperVersion,
    [property: JsonPropertyName("paperStatus")] string? PaperStatus,
    [property: JsonPropertyName("incidents")] IReadOnlyList<InvestigationIncident> Incidents,
    [property: JsonPropertyName("issuedCopies")] IReadOnlyList<InvestigationCopyEvidence> IssuedCopies,
    [property: JsonPropertyName("accessHistory")] IReadOnlyList<InvestigationAuditEntry> AccessHistory,
    [property: JsonPropertyName("auditChainValid")] bool AuditChainValid,
    [property: JsonPropertyName("auditEventsChecked")] long AuditEventsChecked,
    [property: JsonPropertyName("auditChainAssessment")] string AuditChainAssessment,
    [property: JsonPropertyName("resultsTruncated")] bool ResultsTruncated,
    [property: JsonPropertyName("missingEvidence")] IReadOnlyList<string> MissingEvidence,
    [property: JsonPropertyName("limitations")] IReadOnlyList<string> Limitations);
