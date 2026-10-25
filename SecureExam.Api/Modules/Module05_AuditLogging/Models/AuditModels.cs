namespace SecureExam.Api.Models;

public sealed record AuditEvent(
    long Sequence,
    string EventId,
    DateTimeOffset ServerTimestamp,
    string EventType,
    string? UserId,
    string? WorkstationId,
    string? ResourceType,
    string? ResourceId,
    string Outcome,
    string Details,
    string PreviousHash,
    string EventHash);

public sealed record AuditVerificationResult(
    bool Valid,
    long CheckedEvents,
    long? FirstInvalidSequence,
    string Message);

public sealed record AuditClassification(
    string EventType,
    string? ResourceType,
    string? ResourceId,
    string? WorkstationId,
    string Details);
