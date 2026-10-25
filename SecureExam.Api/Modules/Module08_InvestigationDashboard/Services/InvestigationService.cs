using SecureExam.Api.Data;
using SecureExam.Api.Models;

namespace SecureExam.Api.Services;

internal sealed class InvestigationService
{
    private readonly InvestigationStore _investigations;
    private readonly AuditStore _audit;

    public InvestigationService(InvestigationStore investigations, AuditStore audit)
    {
        _investigations = investigations;
        _audit = audit;
    }

    public async Task<InvestigationEvidenceReport> SearchAsync(
        string searchType,
        string searchValue,
        CancellationToken cancellationToken)
    {
        var verification = await _audit.VerifyAsync(cancellationToken);
        var assessment = verification.Valid
            ? $"Verified {verification.CheckedEvents} current audit events. The hash chain is not an independent evidence anchor."
            : $"{verification.Message} First invalid sequence: {verification.FirstInvalidSequence}.";
        return await _investigations.SearchAsync(
            searchType,
            searchValue,
            DateTimeOffset.UtcNow,
            verification.Valid,
            verification.CheckedEvents,
            assessment,
            cancellationToken);
    }
}
