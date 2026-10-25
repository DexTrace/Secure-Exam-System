using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecureExam.Desktop.Models;
using SecureExam.Desktop.Services;

namespace SecureExam.Desktop.Views;

public partial class AlertManagementDashboard : UserControl
{
    private readonly ApiClient _api;

    internal AlertManagementDashboard(ApiClient api)
    {
        InitializeComponent();
        _api = api;
        Loaded += async (_, _) => await LoadAsync();
    }

    private async void RefreshAlertsButton_Click(object sender, RoutedEventArgs e) => await LoadAsync();

    private async Task LoadAsync()
    {
        RefreshAlertsButton.IsEnabled = false;
        StatusText.Text = "Loading alerts and incident cases…";
        try
        {
            var dashboard = await _api.GetAlertsAsync(null);
            AlertList.Children.Clear();
            CaseList.Children.Clear();
            if (dashboard.Alerts.Count == 0)
            {
                AlertList.Children.Add(EmptyState("No security alerts have been generated."));
            }

            foreach (var alert in dashboard.Alerts)
            {
                AlertList.Children.Add(BuildAlertCard(alert));
            }

            if (dashboard.Cases.Count == 0)
            {
                CaseList.Children.Add(EmptyState("No incident cases are open."));
            }

            foreach (var incidentCase in dashboard.Cases)
            {
                CaseList.Children.Add(BuildCaseCard(incidentCase));
            }

            StatusText.Text = $"Showing {dashboard.Alerts.Count} alerts and {dashboard.Cases.Count} incident cases.";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not load security alerts.");
        }
        finally
        {
            RefreshAlertsButton.IsEnabled = true;
        }
    }

    private UIElement BuildAlertCard(SecurityAlert alert)
    {
        var content = new StackPanel();
        var severityColor = alert.Severity == "high"
            ? Color.FromRgb(166, 37, 37)
            : Color.FromRgb(132, 91, 0);
        var heading = new DockPanel();
        var status = new TextBlock
        {
            Text = alert.Status.ToUpperInvariant(),
            FontSize = 10,
            FontWeight = FontWeights.Bold,
            Foreground = alert.Status == "resolved"
                ? new SolidColorBrush(Color.FromRgb(23, 107, 58))
                : new SolidColorBrush(severityColor),
            VerticalAlignment = VerticalAlignment.Center
        };
        DockPanel.SetDock(status, Dock.Right);
        heading.Children.Add(status);
        heading.Children.Add(new TextBlock
        {
            Text = $"{alert.Severity.ToUpperInvariant()} · {alert.Summary}",
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(severityColor),
            TextWrapping = TextWrapping.Wrap
        });
        content.Children.Add(heading);
        content.Children.Add(BodyText(
            $"{alert.AlertType} · {alert.CreatedAt.ToLocalTime():g}\n{alert.Details}\n" +
            $"Account: {alert.ActorUserId ?? "unknown"} · Workstation: {alert.WorkstationId ?? "unknown"} · " +
            $"Resource: {alert.ResourceType ?? "—"} {alert.ResourceId ?? string.Empty}"));

        if (alert.ReviewedByName is not null)
        {
            content.Children.Add(BodyText(
                $"Reviewed by {alert.ReviewedByName} at {alert.ReviewedAt?.ToLocalTime():g}" +
                (string.IsNullOrWhiteSpace(alert.ReviewNote) ? string.Empty : $"\nReview note: {alert.ReviewNote}")));
        }
        if (alert.ResolvedByName is not null)
        {
            content.Children.Add(BodyText($"Resolved by {alert.ResolvedByName} at {alert.ResolvedAt?.ToLocalTime():g}"));
        }

        if (alert.Status != "resolved")
        {
            var controls = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
            var noteInput = new TextBox
            {
                MaxLength = 1000,
                MinHeight = 36,
                Padding = new Thickness(8),
                VerticalContentAlignment = VerticalAlignment.Center,
                ToolTip = "Optional review note; required as the incident case summary or resolution note."
            };
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
            if (alert.Status == "open")
            {
                var review = ActionButton("Mark reviewed", "#EAF0F7", (Brush)FindResource("NavyBrush"));
                review.Click += async (_, _) => await ReviewAsync(alert, noteInput, review);
                buttons.Children.Add(review);
            }

            var createCase = ActionButton("Create incident case", "#FFF4DB", new SolidColorBrush(Color.FromRgb(132, 91, 0)));
            createCase.Margin = new Thickness(6, 0, 0, 0);
            createCase.Click += async (_, _) => await CreateCaseAsync(alert, noteInput, createCase);
            buttons.Children.Add(createCase);

            var resolve = ActionButton("Resolve", "#176B3A", Brushes.White);
            resolve.Margin = new Thickness(6, 0, 0, 0);
            resolve.Click += async (_, _) => await ResolveAsync(alert, noteInput, resolve);
            buttons.Children.Add(resolve);
            controls.Children.Add(noteInput);
            controls.Children.Add(buttons);
            content.Children.Add(controls);
        }

        return Card(content);
    }

    private async Task ReviewAsync(SecurityAlert alert, TextBox note, Button button)
    {
        button.IsEnabled = false;
        try
        {
            await _api.ReviewAlertAsync(alert.AlertId, EmptyToNull(note.Text));
            await LoadAsync();
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not mark the alert reviewed.");
        }
        finally
        {
            button.IsEnabled = true;
        }
    }

    private async Task CreateCaseAsync(SecurityAlert alert, TextBox summary, Button button)
    {
        if (string.IsNullOrWhiteSpace(summary.Text))
        {
            StatusText.Text = "Enter a case summary in the note field before creating an incident case.";
            return;
        }

        button.IsEnabled = false;
        try
        {
            var incidentCase = await _api.CreateAlertCaseAsync(alert.AlertId, summary.Text.Trim());
            StatusText.Text = $"Incident case {incidentCase.CaseId} created and linked to alert {alert.AlertId}.";
            await LoadAsync();
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not create an incident case.");
        }
        finally
        {
            button.IsEnabled = true;
        }
    }

    private async Task ResolveAsync(SecurityAlert alert, TextBox note, Button button)
    {
        if (string.IsNullOrWhiteSpace(note.Text))
        {
            StatusText.Text = "Add a resolution note before resolving the alert.";
            return;
        }

        button.IsEnabled = false;
        try
        {
            await _api.ResolveAlertAsync(alert.AlertId, note.Text.Trim());
            await LoadAsync();
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not resolve the alert.");
        }
        finally
        {
            button.IsEnabled = true;
        }
    }

    private UIElement BuildCaseCard(AlertCase incidentCase)
    {
        var content = new StackPanel();
        content.Children.Add(new TextBlock
        {
            Text = $"{incidentCase.Status.ToUpperInvariant()} · Case {incidentCase.CaseId}",
            FontWeight = FontWeights.SemiBold,
            Foreground = incidentCase.Status == "resolved"
                ? new SolidColorBrush(Color.FromRgb(23, 107, 58))
                : (Brush)FindResource("InkBrush")
        });
        content.Children.Add(BodyText(
            $"{incidentCase.Summary}\nAlert: {incidentCase.AlertId}\n" +
            $"Created by {incidentCase.CreatedByName} · {incidentCase.CreatedAt.ToLocalTime():g}"));
        return Card(content);
    }

    private Border Card(UIElement child) => new()
    {
        Margin = new Thickness(0, 0, 0, 10),
        Padding = new Thickness(16),
        Background = Brushes.White,
        BorderBrush = new SolidColorBrush(Color.FromRgb(227, 233, 240)),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(8),
        Child = child
    };

    private TextBlock BodyText(string text) => new()
    {
        Margin = new Thickness(0, 7, 0, 0),
        Text = text,
        TextWrapping = TextWrapping.Wrap,
        Foreground = (Brush)FindResource("MutedBrush")
    };

    private Button ActionButton(string text, string background, Brush foreground) => new()
    {
        Content = text,
        Background = (Brush)new BrushConverter().ConvertFromString(background)!,
        Foreground = foreground
    };

    private UIElement EmptyState(string text) => new Border
    {
        Padding = new Thickness(16),
        Background = Brushes.White,
        BorderBrush = new SolidColorBrush(Color.FromRgb(227, 233, 240)),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(8),
        Child = BodyText(text)
    };

    private static string? EmptyToNull(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string DescribeError(Exception exception, string fallback) =>
        exception is SessionExpiredException or ApiRequestException ? exception.Message :
        exception is TaskCanceledException ? "The request timed out. Try again." :
        fallback;
}
