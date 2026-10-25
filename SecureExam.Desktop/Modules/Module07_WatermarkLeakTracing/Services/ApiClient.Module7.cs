using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using SecureExam.Desktop.Models;

namespace SecureExam.Desktop.Services;

internal sealed partial class ApiClient
{
    public async Task<WatermarkedCopy> GetWatermarkedCopyAsync(
        string paperId,
        CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"api/papers/{Uri.EscapeDataString(paperId)}/watermarked-copy");
        using var response = await _http.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            EnsureSuccess(response.StatusCode, body);
        }

        var copyId = response.Headers.TryGetValues("X-SecureExam-CopyId", out var copyIds)
            ? copyIds.FirstOrDefault()
            : null;
        var fingerprint = response.Headers.TryGetValues("X-SecureExam-Pdf-Sha256", out var fingerprints)
            ? fingerprints.FirstOrDefault()
            : null;
        if (string.IsNullOrWhiteSpace(copyId) || string.IsNullOrWhiteSpace(fingerprint))
        {
            throw new ApiRequestException("The server returned a PDF without its issuance fingerprint.");
        }

        return new WatermarkedCopy(
            await response.Content.ReadAsByteArrayAsync(cancellationToken),
            copyId,
            fingerprint);
    }

    public async Task<DocumentFingerprintMatch> VerifyRecoveredCopyAsync(
        byte[] pdf,
        CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/document-tracing/verify");
        using var content = new MultipartFormDataContent();
        var document = new ByteArrayContent(pdf);
        document.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        content.Add(document, "document", "recovered-copy.pdf");
        request.Content = content;

        using var response = await _http.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        EnsureSuccess(response.StatusCode, body);
        using var result = JsonDocument.Parse(body);
        return result.RootElement.GetProperty("match").Deserialize<DocumentFingerprintMatch>(JsonOptions)
            ?? throw new ApiRequestException("The server returned an invalid fingerprint match result.");
    }
}
