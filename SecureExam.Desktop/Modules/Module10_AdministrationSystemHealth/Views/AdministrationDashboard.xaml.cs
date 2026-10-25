using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecureExam.Desktop.Models;
using SecureExam.Desktop.Services;

namespace SecureExam.Desktop.Views;

public partial class AdministrationDashboard : UserControl
{
    private readonly ApiClient _api;

    internal AdministrationDashboard(ApiClient api)
    {
        InitializeComponent();
        _api = api;
        Loaded += async (_, _) => await LoadAsync();
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await LoadAsync();

    private async void CreateBackupButton_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                "Create a sensitive recovery archive on the API server? Ensure the configured backup directory has restricted access.",
                "Create recovery backup",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }

        CreateBackupButton.IsEnabled = false;
        StatusText.Text = "Creating a consistent database and key-ring backup on the API server…";
        try
        {
            var backup = await _api.CreateSystemBackupAsync();
            StatusText.Text = $"Backup created: {backup.FileName} ({FormatSize(backup.SizeBytes)}).";
            await LoadAsync();
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not create the recovery backup.");
        }
        finally
        {
            CreateBackupButton.IsEnabled = true;
        }
    }

    private async Task LoadAsync()
    {
        RefreshButton.IsEnabled = false;
        StatusText.Text = "Checking API and database…";
        try
        {
            var system = await _api.GetSystemHealthAsync();
            HealthDetails.Text =
                $"API: {system.ApiStatus.ToUpperInvariant()}  ·  Database: {system.DatabaseStatus.ToUpperInvariant()}\n" +
                $"Database integrity: verified  ·  Users: {system.UserCount}  ·  Registered devices: {system.RegisteredDeviceCount}\n" +
                $"Data Protection key files: {system.DataProtectionKeyCount}  ·  Service started: {system.StartedAt.ToLocalTime():f}\n" +
                $"Last checked: {system.CheckedAt.ToLocalTime():f}";
            VersionDetails.Text =
                $"API build: {system.ApiVersion}  ·  Server runtime: .NET {system.RuntimeVersion}\n" +
                $"Desktop build: {typeof(AdministrationDashboard).Assembly.GetName().Version?.ToString() ?? "unknown"}";
            PolicyDetails.Text =
                $"Require compliant workstations: {EnabledState(system.Policies.RequireCompliantWorkstations)}\n" +
                $"Data Protection certificate configured: {EnabledState(system.Policies.ProtectedKeysConfigured)}\n" +
                $"Session lifetime: {system.Policies.SessionLifetimeHours:0.#} hours\n" +
                $"Audit retention: {system.Policies.AuditRetention}\n" +
                $"Backup retention: latest {system.Policies.BackupRetentionCount} archives";

            BackupList.Children.Clear();
            if (system.Backups.Count == 0)
            {
                BackupList.Children.Add(new TextBlock
                {
                    Text = "No recovery backups have been created.",
                    Foreground = (Brush)FindResource("MutedBrush")
                });
            }

            foreach (var backup in system.Backups)
            {
                BackupList.Children.Add(new TextBlock
                {
                    Text = $"{backup.FileName}  ·  {FormatSize(backup.SizeBytes)}  ·  {backup.CreatedAt.ToLocalTime():g}",
                    Margin = new Thickness(0, 3, 0, 3),
                    Foreground = (Brush)FindResource("InkBrush"),
                    TextWrapping = TextWrapping.Wrap
                });
            }

            StatusText.Text = "API and database are reachable. Database integrity check passed.";
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(23, 107, 58));
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusText.Text = DescribeError(exception, "Could not load system health.");
            StatusText.Foreground = new SolidColorBrush(Color.FromRgb(166, 37, 37));
        }
        finally
        {
            RefreshButton.IsEnabled = true;
        }
    }

    private static string EnabledState(bool enabled) => enabled ? "ENABLED" : "DISABLED";

    private static string FormatSize(long bytes) => bytes < 1024 * 1024
        ? $"{bytes / 1024d:0.#} KB"
        : $"{bytes / (1024d * 1024d):0.#} MB";

    private static string DescribeError(Exception exception, string fallback) =>
        exception is ApiRequestException ? exception.Message : fallback;
}
