namespace SecureExam.Api.Models;

public sealed record PaperSection(string Name, int Marks);
public sealed record PaperRun(string Text, bool Bold, bool Italic, bool Underline);
public sealed record PaperParagraph(IReadOnlyList<PaperRun> Runs);
public sealed record PaperDocument(IReadOnlyList<PaperParagraph> Paragraphs);

public sealed record PaperDraftRequest(
    string Title,
    string Subject,
    string ExamCode,
    IReadOnlyList<PaperSection> Sections,
    int TotalMarks,
    string Instructions,
    PaperDocument Content);

public sealed record PaperSummary(
    string PaperId,
    string OwnerId,
    string OwnerName,
    string Title,
    string Subject,
    string ExamCode,
    IReadOnlyList<PaperSection> Sections,
    int TotalMarks,
    string Instructions,
    PaperDocument Content,
    string Status,
    int Version,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? SubmittedAt,
    DateTimeOffset? ApprovedAt,
    string? ApprovedBy)
{
    public string? IssuedCopyId { get; init; }
    public string? ReviewerComment { get; init; }
    public string? ReviewerDecision { get; init; }
}

public sealed record PaperVersionSummary(
    int Version,
    string Action,
    string ChangedBy,
    DateTimeOffset ChangedAt,
    PaperSummary Paper);

public sealed record PaperTransitionRequest(string Action, string? Comment = null);
public sealed record CreateDistributionGrantRequest(string PaperId, string RecipientUserId, DateTimeOffset? ExpiresAt);

public sealed record DistributionGrant(
    string GrantId,
    string PaperId,
    string PaperTitle,
    string RecipientUserId,
    string RecipientName,
    string RecipientEmail,
    string GrantedBy,
    DateTimeOffset IssuedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt);

public sealed record IssuedPaperCopy(
    string CopyId,
    string PaperId,
    string RecipientUserId,
    string Action,
    DateTimeOffset IssuedAt,
    string ContentSha256);

public sealed record ProtectedPaperPayload(
    string Title,
    string Subject,
    string ExamCode,
    IReadOnlyList<PaperSection> Sections,
    int TotalMarks,
    string Instructions,
    PaperDocument Content);

public sealed record PaperAccessEvent(
    string EventId,
    string PaperId,
    string PaperTitle,
    string UserId,
    string UserName,
    string Action,
    string ContentSha256,
    DateTimeOffset OccurredAt);
