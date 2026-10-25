namespace SecureExam.Api.Models;

public sealed record DocumentFingerprintMatch(
    bool MatchFound,
    string? CopyId,
    string? PaperId,
    string? PaperTitle,
    int? PaperVersion,
    string? RecipientUserId,
    string? RecipientName,
    string? RecipientEmail,
    DateTimeOffset? IssuedAt,
    string FingerprintSha256);
