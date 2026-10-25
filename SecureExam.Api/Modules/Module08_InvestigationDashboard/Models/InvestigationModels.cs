namespace SecureExam.Api.Models;

public sealed record CreateInvestigationIncidentRequest(
    string Summary,
    string? PaperId,
    string? CopyId);

public sealed record InvestigationIncident(
    string IncidentId,
    string Summary,
    string? PaperId,
    string? CopyId,
    string CreatedBy,
    string CreatedByName,
    DateTimeOffset CreatedAt);

public sealed record InvestigationAuditEntry(
    long Sequence,
    string EventId,
    DateTimeOffset ServerTimestamp,
    string EventType,
    string? UserId,
    string? WorkstationId,
    string? WorkstationName,
    string? Centre,
    string? Room,
    string? AssignedWorkstationId,
    string? ResourceType,
    string? ResourceId,
    string Outcome,
    string Details,
    string EventHash);

public sealed record InvestigationCopyEvidence(
    string CopyId,
    string PaperId,
    string PaperTitle,
    int? PaperVersion,
    string RecipientUserId,
    string? RecipientName,
    string? RecipientEmail,
    string Action,
    DateTimeOffset IssuedAt,
    string ContentSha256,
    string? PdfSha256);

public sealed record InvestigationEvidenceReport(
    string SearchType,
    string SearchValue,
    DateTimeOffset GeneratedAt,
    string? PaperId,
    string? PaperTitle,
    int? CurrentPaperVersion,
    string? PaperStatus,
    IReadOnlyList<InvestigationIncident> Incidents,
    IReadOnlyList<InvestigationCopyEvidence> IssuedCopies,
    IReadOnlyList<InvestigationAuditEntry> AccessHistory,
    bool AuditChainValid,
    long AuditEventsChecked,
    string AuditChainAssessment,
    bool ResultsTruncated,
    IReadOnlyList<string> MissingEvidence,
    IReadOnlyList<string> Limitations);
