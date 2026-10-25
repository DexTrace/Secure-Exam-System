using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using SecureExam.Desktop.Models;
using SecureExam.Desktop.Services;

namespace SecureExam.Desktop.Views;

public partial class InvestigationDashboard : UserControl
{
    private static readonly JsonSerializerOptions ReportJsonOptions = new() { WriteIndented = true };
    private readonly ApiClient _api;
    private InvestigationEvidenceReport? _report;

    internal InvestigationDashboard(ApiClient api)
    {
        InitializeComponent();
        _api = api;
    }

    private async void SearchButton_Click(object sender, RoutedEventArgs e)
    {
        var type = (SearchTypeInput.SelectedItem as ComboBoxItem)?.Tag as string;
        var query = SearchValueInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(type) || query.Length == 0)
        {
            StatusText.Text = "Choose a search type and enter an identifier.";
            return;
        }

        SearchButton.IsEnabled = false;
        StatusText.Text = "Searching evidence and verifying the audit chain…";
        try
        {
            _report = await _api.SearchInvestigationAsync(type, query);
            SaveReportButton.IsEnabled = true;
            RenderReport(_report);
            StatusText.Text = $"Evidence report generated at {_report.GeneratedAt.ToLocalTime():g}.";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not search investigation evidence.");
        }
        finally
        {
            SearchButton.IsEnabled = true;
        }
    }

    private async void CreateIncidentButton_Click(object sender, RoutedEventArgs e)
    {
        var summary = IncidentSummaryInput.Text.Trim();
        var paperId = EmptyToNull(IncidentPaperIdInput.Text);
        var copyId = EmptyToNull(IncidentCopyIdInput.Text);
        if (summary.Length == 0 || (paperId is null && copyId is null))
        {
            StatusText.Text = "Enter an incident summary and link a paper ID or copy ID.";
            return;
        }

        CreateIncidentButton.IsEnabled = false;
        try
        {
            var incident = await _api.CreateInvestigationIncidentAsync(
                new CreateInvestigationIncidentRequest(summary, paperId, copyId));
            IncidentSummaryInput.Clear();
            IncidentPaperIdInput.Clear();
            IncidentCopyIdInput.Clear();
            StatusText.Text = $"Incident {incident.IncidentId} created. Search by this ID to open its evidence report.";
            SearchTypeInput.SelectedIndex = 2;
            SearchValueInput.Text = incident.IncidentId;
            await SearchButton_ClickAsync("incident", incident.IncidentId);
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not register the incident.");
        }
        finally
        {
            CreateIncidentButton.IsEnabled = true;
        }
    }

    private async Task SearchButton_ClickAsync(string type, string query)
    {
        try
        {
            _report = await _api.SearchInvestigationAsync(type, query);
            SaveReportButton.IsEnabled = true;
            RenderReport(_report);
            StatusText.Text = $"Evidence report generated at {_report.GeneratedAt.ToLocalTime():g}.";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not open the incident evidence report.");
        }
    }

    private void SaveReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Save investigation evidence report",
            FileName = $"investigation-{SafeFileName(_report.SearchValue)}.json",
            DefaultExt = ".json",
            Filter = "JSON evidence report (*.json)|*.json",
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true)
        {
            return;
        }

        try
        {
            var json = JsonSerializer.Serialize(_report, ReportJsonOptions);
            File.WriteAllText(dialog.FileName, json, new UTF8Encoding(false));
            StatusText.Text = $"Evidence report saved to {dialog.FileName}. Protect the exported report as sensitive evidence.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            StatusText.Text = $"Could not save evidence report: {exception.Message}";
        }
    }

    private void RenderReport(InvestigationEvidenceReport report)
    {
        ReportPanel.Children.Clear();
        AddCard("Search", $"{report.SearchType.ToUpperInvariant()} · {report.SearchValue}\nGenerated (server UTC): {report.GeneratedAt:O}");
        if (report.PaperId is not null)
        {
            AddCard("Paper", $"{report.PaperTitle ?? "Unknown paper"}\nID: {report.PaperId} · Current version: {report.CurrentPaperVersion?.ToString() ?? "unknown"} · Status: {report.PaperStatus ?? "unknown"}");
        }

        var chainColor = report.AuditChainValid
            ? Color.FromRgb(23, 107, 58)
            : Color.FromRgb(166, 37, 37);
        AddCard("Audit-chain assessment",
            $"{report.AuditChainAssessment}\nChecked events: {report.AuditEventsChecked}",
            new SolidColorBrush(chainColor));

        if (report.MissingEvidence.Count > 0)
        {
            AddCard("Missing or unavailable evidence", string.Join("\n• ", report.MissingEvidence.Prepend(string.Empty)));
        }

        if (report.Incidents.Count > 0)
        {
            AddCard("Related incidents", string.Join("\n\n", report.Incidents.Select(incident =>
                $"{incident.IncidentId} · {incident.CreatedAt.ToLocalTime():g}\n{incident.Summary}\nCreated by {incident.CreatedByName}")));
        }

        if (report.IssuedCopies.Count > 0)
        {
            AddCard($"Issued copies ({report.IssuedCopies.Count})", string.Join("\n\n", report.IssuedCopies.Select(copy =>
                $"{copy.CopyId} · {copy.Action.ToUpperInvariant()} · {copy.IssuedAt.ToLocalTime():g}\n" +
                $"Recipient: {copy.RecipientName ?? "unknown"} ({copy.RecipientEmail ?? copy.RecipientUserId}) · Paper version: {copy.PaperVersion?.ToString() ?? "not fingerprinted"}\n" +
                $"Content SHA-256: {copy.ContentSha256}\nPDF SHA-256: {copy.PdfSha256 ?? "not recorded"}")));
        }

        if (report.AccessHistory.Count > 0)
        {
            AddCard($"Relevant access history ({report.AccessHistory.Count})", string.Join("\n\n", report.AccessHistory.Select(entry =>
            {
                var workstation = entry.WorkstationName is null
                    ? $"Unmapped device {entry.WorkstationId ?? "unknown"}"
                    : $"{entry.WorkstationName} · {entry.Centre}, {entry.Room} · workstation {entry.AssignedWorkstationId}";
                return $"#{entry.Sequence} · {entry.ServerTimestamp.ToLocalTime():g} · {entry.EventType} · {entry.Outcome}\n" +
                       $"User: {entry.UserId ?? "unknown"} · {workstation}\n{entry.Details}\nEvent hash: {entry.EventHash}";
            })));
        }

        AddCard("Limitations", string.Join("\n• ", report.Limitations.Prepend(string.Empty)));
    }

    private void AddCard(string title, string body, Brush? titleBrush = null)
    {
        var content = new StackPanel();
        content.Children.Add(new TextBlock
        {
            Text = title,
            FontWeight = FontWeights.SemiBold,
            Foreground = titleBrush ?? (Brush)FindResource("InkBrush")
        });
        content.Children.Add(new TextBlock
        {
            Margin = new Thickness(0, 7, 0, 0),
            Text = body,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)FindResource("MutedBrush")
        });
        ReportPanel.Children.Add(new Border
        {
            Margin = new Thickness(0, 0, 0, 10),
            Padding = new Thickness(16),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(227, 233, 240)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Child = content
        });
    }

    private static string? EmptyToNull(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string SafeFileName(string value)
    {
        var safe = string.Concat(value.Select(character =>
            Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));
        return string.IsNullOrWhiteSpace(safe) ? "report" : safe;
    }

    private static string DescribeError(Exception exception, string fallback) =>
        exception is SessionExpiredException ? exception.Message :
        exception is ApiRequestException ? exception.Message :
        exception is TaskCanceledException ? "The request timed out. Try again." :
        fallback;
}
