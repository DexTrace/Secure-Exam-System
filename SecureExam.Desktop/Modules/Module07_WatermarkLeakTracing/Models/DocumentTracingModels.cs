namespace SecureExam.Desktop.Models;

internal sealed record WatermarkedCopy(byte[] Pdf, string CopyId, string FingerprintSha256);

internal sealed record DocumentFingerprintMatch(
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
