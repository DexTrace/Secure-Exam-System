using System.Text.Json.Serialization;

namespace SecureExam.Desktop.Models;

public sealed class PaperSection
{
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("marks")] public int Marks { get; init; }
}

public sealed class PaperRun
{
    [JsonPropertyName("text")] public string Text { get; init; } = string.Empty;
    [JsonPropertyName("bold")] public bool Bold { get; init; }
    [JsonPropertyName("italic")] public bool Italic { get; init; }
    [JsonPropertyName("underline")] public bool Underline { get; init; }
}

public sealed class PaperParagraph
{
    [JsonPropertyName("runs")] public IReadOnlyList<PaperRun> Runs { get; init; } = Array.Empty<PaperRun>();
}

public sealed class PaperDocument
{
    [JsonPropertyName("paragraphs")] public IReadOnlyList<PaperParagraph> Paragraphs { get; init; } = Array.Empty<PaperParagraph>();
}

public sealed class PaperDraftRequest
{
    [JsonPropertyName("title")] public string Title { get; init; } = string.Empty;
    [JsonPropertyName("subject")] public string Subject { get; init; } = string.Empty;
    [JsonPropertyName("examCode")] public string ExamCode { get; init; } = string.Empty;
    [JsonPropertyName("sections")] public IReadOnlyList<PaperSection> Sections { get; init; } = Array.Empty<PaperSection>();
    [JsonPropertyName("totalMarks")] public int TotalMarks { get; init; }
    [JsonPropertyName("instructions")] public string Instructions { get; init; } = string.Empty;
    [JsonPropertyName("content")] public PaperDocument Content { get; init; } = new();
}

public sealed class PaperSummary
{
    [JsonPropertyName("paperId")] public string PaperId { get; init; } = string.Empty;
    [JsonPropertyName("ownerId")] public string OwnerId { get; init; } = string.Empty;
    [JsonPropertyName("ownerName")] public string OwnerName { get; init; } = string.Empty;
    [JsonPropertyName("title")] public string Title { get; init; } = string.Empty;
    [JsonPropertyName("subject")] public string Subject { get; init; } = string.Empty;
    [JsonPropertyName("examCode")] public string ExamCode { get; init; } = string.Empty;
    [JsonPropertyName("sections")] public IReadOnlyList<PaperSection> Sections { get; init; } = Array.Empty<PaperSection>();
    [JsonPropertyName("totalMarks")] public int TotalMarks { get; init; }
    [JsonPropertyName("instructions")] public string Instructions { get; init; } = string.Empty;
    [JsonPropertyName("content")] public PaperDocument Content { get; init; } = new();
    [JsonPropertyName("status")] public string Status { get; init; } = string.Empty;
    [JsonPropertyName("version")] public int Version { get; init; }
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; init; }
    [JsonPropertyName("updatedAt")] public DateTimeOffset UpdatedAt { get; init; }
    [JsonPropertyName("submittedAt")] public DateTimeOffset? SubmittedAt { get; init; }
    [JsonPropertyName("approvedAt")] public DateTimeOffset? ApprovedAt { get; init; }
    [JsonPropertyName("approvedBy")] public string? ApprovedBy { get; init; }
    [JsonPropertyName("issuedCopyId")] public string? IssuedCopyId { get; init; }
    [JsonPropertyName("reviewerComment")] public string? ReviewerComment { get; init; }
    [JsonPropertyName("reviewerDecision")] public string? ReviewerDecision { get; init; }
}

public sealed class PaperVersion
{
    [JsonPropertyName("version")] public int Version { get; init; }
    [JsonPropertyName("action")] public string Action { get; init; } = string.Empty;
    [JsonPropertyName("changedBy")] public string ChangedBy { get; init; } = string.Empty;
    [JsonPropertyName("changedAt")] public DateTimeOffset ChangedAt { get; init; }
    [JsonPropertyName("paper")] public PaperSummary Paper { get; init; } = new();
}

public sealed class PaperAccessResult
{
    [JsonPropertyName("paper")] public PaperSummary Paper { get; init; } = new();
    [JsonPropertyName("integritySha256")] public string IntegritySha256 { get; init; } = string.Empty;
    [JsonPropertyName("issuedCopyId")] public string IssuedCopyId { get; init; } = string.Empty;
}

public sealed class DistributionGrant
{
    [JsonPropertyName("grantId")] public string GrantId { get; init; } = string.Empty;
    [JsonPropertyName("paperId")] public string PaperId { get; init; } = string.Empty;
    [JsonPropertyName("paperTitle")] public string PaperTitle { get; init; } = string.Empty;
    [JsonPropertyName("recipientUserId")] public string RecipientUserId { get; init; } = string.Empty;
    [JsonPropertyName("recipientName")] public string RecipientName { get; init; } = string.Empty;
    [JsonPropertyName("recipientEmail")] public string RecipientEmail { get; init; } = string.Empty;
    [JsonPropertyName("grantedBy")] public string GrantedBy { get; init; } = string.Empty;
    [JsonPropertyName("issuedAt")] public DateTimeOffset IssuedAt { get; init; }
    [JsonPropertyName("expiresAt")] public DateTimeOffset? ExpiresAt { get; init; }
    [JsonPropertyName("revokedAt")] public DateTimeOffset? RevokedAt { get; init; }
}

public sealed class IssuedPaperCopy
{
    [JsonPropertyName("copyId")] public string CopyId { get; init; } = string.Empty;
    [JsonPropertyName("paperId")] public string PaperId { get; init; } = string.Empty;
    [JsonPropertyName("recipientUserId")] public string RecipientUserId { get; init; } = string.Empty;
    [JsonPropertyName("action")] public string Action { get; init; } = string.Empty;
    [JsonPropertyName("issuedAt")] public DateTimeOffset IssuedAt { get; init; }
    [JsonPropertyName("contentSha256")] public string ContentSha256 { get; init; } = string.Empty;
}

public sealed class PaperAccessEvent
{
    [JsonPropertyName("eventId")] public string EventId { get; init; } = string.Empty;
    [JsonPropertyName("paperId")] public string PaperId { get; init; } = string.Empty;
    [JsonPropertyName("paperTitle")] public string PaperTitle { get; init; } = string.Empty;
    [JsonPropertyName("userId")] public string UserId { get; init; } = string.Empty;
    [JsonPropertyName("userName")] public string UserName { get; init; } = string.Empty;
    [JsonPropertyName("action")] public string Action { get; init; } = string.Empty;
    [JsonPropertyName("contentSha256")] public string ContentSha256 { get; init; } = string.Empty;
    [JsonPropertyName("occurredAt")] public DateTimeOffset OccurredAt { get; init; }
}
