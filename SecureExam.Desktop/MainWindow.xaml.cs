using System.Net.Http;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using SecureExam.Desktop.Controls;
using SecureExam.Desktop.Models;
using SecureExam.Desktop.Services;
using SecureExam.Desktop.Views;

namespace SecureExam.Desktop;

public partial class MainWindow : Window
{
    private readonly ApiClient _api = new();
    private readonly DeviceIdentity _device;
    private readonly Dictionary<string, NavigationItem> _navigation = new();
    private readonly DispatcherTimer _sessionTimer = new() { Interval = TimeSpan.FromSeconds(45) };
    private SessionUser? _user;
    private LoginChallenge? _challenge;
    private DateTimeOffset? _expiresAt;
    private string _activePage = "overview";
    private PaperWorkspace? _paperWorkspace;
    private bool _checkingSession;

    public MainWindow()
    {
        InitializeComponent();
        _device = DeviceIdentity.LoadOrCreate();
        _sessionTimer.Tick += SessionTimer_Tick;
        MfaCodeInput.PreviewKeyDown += MfaCodeInput_PreviewKeyDown;
        MfaCodeInput.PreviewTextInput += MfaCodeInput_PreviewTextInput;
    }

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        if (_challenge is null)
        {
            await BeginSignInAsync();
        }
        else
        {
            await CompleteMfaAsync();
        }
    }

    private async Task BeginSignInAsync()
    {
        var email = EmailInput.Text.Trim();
        var password = PasswordInput.Value;
        if (email.Length == 0 || password.Length == 0)
        {
            LoginMessage.Text = "Enter your email address and password.";
            return;
        }

        SetBusy(true);
        LoginMessage.Text = string.Empty;
        try
        {
            _challenge = await _api.LoginAsync(email, password, _device);
            LoginHeading.Text = _challenge.State == "mfa_setup_required"
                ? "Set up multi-factor sign-in"
                : "Verify your identity";
            LoginSubheading.Text = _challenge.Message;
            CredentialsPanel.Visibility = Visibility.Collapsed;
            MfaPanel.Visibility = Visibility.Visible;
            MfaSetupPanel.Visibility = _challenge.State == "mfa_setup_required"
                ? Visibility.Visible
                : Visibility.Collapsed;
            MfaSecretText.Text = _challenge.Secret ?? string.Empty;
            MfaCodeInput.Clear();
            LoginButton.Content = "Verify and continue";
            BackButton.Visibility = Visibility.Visible;
            MfaCodeInput.Focus();
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            LoginMessage.Text = DescribeError(exception, "Could not reach the authentication service.");
        }
        finally
        {
            PasswordInput.Clear();
            SetBusy(false);
        }
    }

    private async Task CompleteMfaAsync()
    {
        var code = MfaCodeInput.Text.Trim();
        if (code.Length != 6 || code.Any(character => !char.IsDigit(character)))
        {
            LoginMessage.Text = "Enter the current six-digit code from your authenticator.";
            return;
        }

        SetBusy(true);
        LoginMessage.Text = string.Empty;
        try
        {
            var result = await _api.CompleteMfaAsync(
                _challenge!.ChallengeId,
                code,
                _device,
                _challenge.State == "mfa_setup_required");
            _challenge = null;

            if (result.State == "device_pending")
            {
                MfaPanel.Visibility = Visibility.Collapsed;
                LoginHeading.Text = "Workstation approval required";
                LoginSubheading.Text = "Your account is protected. An administrator must approve this workstation before it can access the system.";
                LoginMessage.Text = result.Message;
                LoginMessage.Foreground = (Brush)FindResource("MutedBrush");
                LoginButton.Visibility = Visibility.Collapsed;
                MfaCodeInput.Clear();
                return;
            }

            if (result.State == "workstation_noncompliant")
            {
                MfaPanel.Visibility = Visibility.Collapsed;
                LoginHeading.Text = "Workstation policy requirements not met";
                LoginSubheading.Text = "This computer cannot sign in until its managed Windows policies are corrected.";
                LoginMessage.Text = result.Message;
                LoginMessage.Foreground = (Brush)FindResource("MutedBrush");
                LoginButton.Visibility = Visibility.Collapsed;
                MfaCodeInput.Clear();
                return;
            }

            if (result.State != "authenticated" || result.User is null)
            {
                throw new ApiRequestException(result.Message ?? "Sign-in could not be completed.");
            }

            _user = result.User;
            _expiresAt = result.ExpiresAt;
            LoginMessage.Foreground = new SolidColorBrush(Color.FromRgb(180, 35, 24));
            ShowApplication();
            _sessionTimer.Start();
            await OpenPageAsync("overview");
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            LoginMessage.Text = DescribeError(exception, "Could not verify the authenticator code.");
        }
        finally
        {
            MfaCodeInput.Clear();
            SetBusy(false);
        }
    }

    private void BackButton_Click(object sender, RoutedEventArgs e) => ResetLogin();

    private void ResetLogin()
    {
        _challenge = null;
        LoginHeading.Text = "Welcome back";
        LoginSubheading.Text = "Sign in with your Secure Exam account.";
        CredentialsPanel.Visibility = Visibility.Visible;
        MfaPanel.Visibility = Visibility.Collapsed;
        MfaSetupPanel.Visibility = Visibility.Collapsed;
        LoginButton.Content = "Continue";
        LoginButton.Visibility = Visibility.Visible;
        BackButton.Visibility = Visibility.Collapsed;
        LoginMessage.Text = string.Empty;
        LoginMessage.Foreground = new SolidColorBrush(Color.FromRgb(180, 35, 24));
        PasswordInput.Clear();
        MfaCodeInput.Clear();
    }

    private void MfaCodeInput_PreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        e.Handled = e.Text.Any(character => !char.IsDigit(character));
    }

    private async void MfaCodeInput_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            await CompleteMfaAsync();
        }
    }

    private void ShowApplication()
    {
        if (_user is null)
        {
            return;
        }

        LoginScreen.Visibility = Visibility.Collapsed;
        ApplicationScreen.Visibility = Visibility.Visible;
        UserNameLabel.Text = _user.DisplayName;
        UserRoleLabel.Text = $"{FormatRole(_user.Role)}  ·  {_user.Email}";
        BuildNavigation();
        UpdateSessionExpiryLabel();
    }

    private void BuildNavigation()
    {
        NavigationPanel.Children.Clear();
        _navigation.Clear();
        AddNavigationSection("WORKSPACE");
        AddNavigationItem("overview", "Overview");
        AddNavigationItem("papers", "Question papers");
        AddNavigationSection("ACCOUNT");
        AddNavigationItem("security", "Account security");
        if (_user?.Role == "admin")
        {
            AddNavigationSection("ADMINISTRATION");
            AddNavigationItem("users", "User accounts");
            AddNavigationItem("devices", "Workstations");
            AddNavigationItem("audit", "Audit log");
            AddNavigationItem("distribution", "Distribution");
            AddNavigationItem("administration", "Administration & health");
        }
        if (_user?.Role is "admin" or "investigator")
        {
            AddNavigationSection("SECURITY OPERATIONS");
            AddNavigationItem("investigation", "Investigation");
            AddNavigationItem("alerts", "Alerts & incidents");
        }
    }

    private void AddNavigationSection(string title)
    {
        NavigationPanel.Children.Add(new TextBlock
        {
            Text = title,
            Margin = new Thickness(12, 18, 8, 7),
            Foreground = new SolidColorBrush(Color.FromRgb(143, 169, 195)),
            FontSize = 9,
            FontWeight = FontWeights.Bold
        });
    }

    private void AddNavigationItem(string key, string title)
    {
        var selected = key == "overview";
        var button = new Button
        {
            Content = title,
            Tag = key,
            Height = 42,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(13, 8, 10, 8),
            Margin = new Thickness(0, 1, 0, 1),
            Background = selected
                ? new SolidColorBrush(Color.FromRgb(36, 74, 118))
                : Brushes.Transparent,
            BorderBrush = selected
                ? new SolidColorBrush(Color.FromRgb(57, 184, 154))
                : Brushes.Transparent,
            Foreground = Brushes.White,
            BorderThickness = new Thickness(selected ? 2 : 1, 1, 1, 1)
        };
        button.Click += NavigationButton_Click;
        NavigationPanel.Children.Add(button);
        _navigation.Add(key, new NavigationItem(title, button));
    }

    private async void NavigationButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string key })
        {
            await OpenPageAsync(key);
        }
    }

    private async Task OpenPageAsync(string page)
    {
        if (!_navigation.TryGetValue(page, out var item) || _user is null)
        {
            return;
        }

        if (_paperWorkspace is not null)
        {
            if (!await _paperWorkspace.SavePendingChangesAsync())
            {
                StatusMessage.Text = "Draft changes could not be saved. Check the connection and save again before leaving this page.";
                return;
            }

            _paperWorkspace.ClearSensitiveState();
            _paperWorkspace = null;
        }

        _activePage = page;
        PageTitle.Text = item.Title;
        PageDescription.Text = page switch
        {
            "overview" => "Authentication and access controls for your Secure Exam workspace.",
            "papers" => "Create, format, autosave, submit, and review secure question papers.",
            "security" => "Review the protections currently applied to your signed-in session.",
            "users" => "Create accounts and manage role assignments. New users must enroll in MFA.",
            "devices" => "Approve registered computers, assign their centre/room/workstation ID, and review Windows policy status.",
            "audit" => "Review server-recorded activity and verify the append-only hash chain.",
            "distribution" => "Authorize paper recipients, set grant expiry, and revoke access.",
            "administration" => "Monitor API and database health, review effective policies, and create recovery backups.",
            "investigation" => "Search evidence by paper, copy, or incident ID; review access history and export a limitations-aware report.",
            "alerts" => "Review server-generated security alerts, create incident cases, and record who resolved each alert.",
            _ => string.Empty
        };
        DashboardCards.Visibility = page == "overview" ? Visibility.Visible : Visibility.Collapsed;
        ModuleContent.Children.Clear();
        StatusMessage.Text = string.Empty;
        UpdateNavigationSelection(page);
        SetBusy(true);

        try
        {
            switch (page)
            {
                case "overview":
                    RenderOverview();
                    break;
                case "papers":
                    _paperWorkspace = new PaperWorkspace(_api, _user);
                    ModuleContent.Children.Add(_paperWorkspace);
                    break;
                case "security":
                    await RenderSecurityAsync();
                    break;
                case "users":
                    await RenderUsersAsync();
                    break;
                case "devices":
                    await RenderDevicesAsync();
                    break;
                case "audit":
                    await RenderAuditAsync();
                    break;
                case "distribution":
                    await RenderDistributionAsync();
                    break;
                case "investigation":
                    ModuleContent.Children.Add(new InvestigationDashboard(_api));
                    break;
                case "alerts":
                    ModuleContent.Children.Add(new AlertManagementDashboard(_api));
                    break;
                case "administration":
                    ModuleContent.Children.Add(new AdministrationDashboard(_api));
                    break;
            }
        }
        catch (SessionExpiredException exception)
        {
            ReturnToLogin(exception.Message);
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusMessage.Text = DescribeError(exception, "The authentication service could not be reached.");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task RenderAuditAsync()
    {
        var events = await _api.GetAuditEventsAsync();
        var verification = await _api.VerifyAuditChainAsync();
        var verificationColor = verification.Valid
            ? Color.FromRgb(23, 107, 58)
            : Color.FromRgb(166, 37, 37);
        var verifyBanner = new Border
        {
            Background = new SolidColorBrush(verification.Valid
                ? Color.FromRgb(231, 245, 236)
                : Color.FromRgb(253, 236, 236)),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(16),
            Margin = new Thickness(0, 0, 0, 14),
            Child = new TextBlock
            {
                Text = $"{verification.Message}  ·  {verification.CheckedEvents} events" +
                       (verification.FirstInvalidSequence is null
                           ? string.Empty
                           : $"  ·  First invalid sequence: {verification.FirstInvalidSequence}"),
                Foreground = new SolidColorBrush(verificationColor),
                TextWrapping = TextWrapping.Wrap,
                FontWeight = FontWeights.SemiBold
            }
        };
        ModuleContent.Children.Add(Section("Hash-chain verification", verifyBanner));

        var list = new StackPanel();
        if (events.Count == 0)
        {
            list.Children.Add(EmptyState("No audit events have been recorded."));
        }

        foreach (var auditEvent in events)
        {
            var entry = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
            entry.Children.Add(TitleText(
                $"#{auditEvent.Sequence}  {auditEvent.EventType.Replace('_', ' ').ToUpperInvariant()}  ·  {auditEvent.Outcome.ToUpperInvariant()}"));
            entry.Children.Add(BodyText(
                $"{auditEvent.ServerTimestamp.ToLocalTime():f}  ·  User: {auditEvent.UserId ?? "unauthenticated"}\n" +
                $"Workstation: {auditEvent.WorkstationId ?? "unknown"}  ·  Resource: {auditEvent.ResourceType ?? "—"} {auditEvent.ResourceId ?? string.Empty}\n" +
                $"{auditEvent.Details}\nHash: {auditEvent.EventHash}"));
            list.Children.Add(entry);
            list.Children.Add(new Border
            {
                Height = 1,
                Margin = new Thickness(0, 0, 0, 12),
                Background = new SolidColorBrush(Color.FromRgb(231, 237, 245))
            });
        }

        ModuleContent.Children.Add(Section($"Recent audit events ({events.Count})", list));
    }

    private async Task RenderDistributionAsync()
    {
        var papers = await _api.GetPapersAsync();
        var users = await _api.GetUsersAsync();
        var grants = await _api.GetDistributionGrantsAsync();
        var copies = await _api.GetIssuedCopiesAsync();
        var approvedPapers = papers.Where(paper => paper.Status == "approved").ToArray();
        var activeUsers = users.Where(user => user.Status == "active").ToArray();
        var form = new StackPanel();
        var paperPicker = new ComboBox
        {
            Height = 40,
            Margin = new Thickness(0, 6, 0, 10),
            Padding = new Thickness(9),
            ItemsSource = approvedPapers,
            DisplayMemberPath = nameof(PaperSummary.Title),
            SelectedIndex = approvedPapers.Length > 0 ? 0 : -1
        };
        var recipientPicker = new ComboBox
        {
            Height = 40,
            Margin = new Thickness(0, 6, 0, 10),
            Padding = new Thickness(9),
            ItemsSource = activeUsers,
            DisplayMemberPath = nameof(UserSummary.Email),
            SelectedIndex = activeUsers.Length > 0 ? 0 : -1
        };
        var expiryInput = NewTextBox("Optional expiry, e.g. 2026-12-31 18:00");
        var grantButton = new Button
        {
            Content = "Authorize recipient",
            Background = (Brush)FindResource("NavyBrush"),
            Foreground = Brushes.White,
            HorizontalAlignment = HorizontalAlignment.Left,
            IsEnabled = approvedPapers.Length > 0 && activeUsers.Length > 0
        };
        grantButton.Click += async (_, _) =>
        {
            if (paperPicker.SelectedItem is not PaperSummary selectedPaper ||
                recipientPicker.SelectedItem is not UserSummary selectedRecipient)
            {
                StatusMessage.Text = "Select an approved paper and active recipient.";
                return;
            }

            DateTimeOffset? expiresAt = null;
            if (!string.IsNullOrWhiteSpace(expiryInput.Text))
            {
                if (!DateTimeOffset.TryParse(
                        expiryInput.Text,
                        CultureInfo.CurrentCulture,
                        DateTimeStyles.AssumeLocal,
                        out var parsedExpiry) ||
                    parsedExpiry <= DateTimeOffset.Now)
                {
                    StatusMessage.Text = "Enter an expiry date/time in the future, or leave it blank for no expiry.";
                    return;
                }

                expiresAt = parsedExpiry.ToUniversalTime();
            }

            grantButton.IsEnabled = false;
            try
            {
                await _api.CreateDistributionGrantAsync(
                    selectedPaper.PaperId, selectedRecipient.UserId, expiresAt);
                StatusMessage.Text = $"Access authorized for {selectedRecipient.Email}.";
                await OpenPageAsync("distribution");
            }
            catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
            {
                StatusMessage.Text = DescribeError(exception, "Could not authorize the recipient.");
            }
            finally
            {
                grantButton.IsEnabled = true;
            }
        };
        form.Children.Add(Field("Approved paper", paperPicker));
        form.Children.Add(Field("Recipient account", recipientPicker));
        form.Children.Add(Field("Grant expiry (local time, optional)", expiryInput));
        form.Children.Add(grantButton);
        if (approvedPapers.Length == 0)
        {
            form.Children.Add(BodyText("Approve a paper before issuing recipient access."));
        }

        ModuleContent.Children.Add(Section("Authorize paper distribution", form));

        var grantList = new StackPanel();
        if (grants.Count == 0)
        {
            grantList.Children.Add(EmptyState("No recipient access grants have been issued."));
        }

        foreach (var grant in grants)
        {
            var revoked = grant.RevokedAt is not null;
            var expired = grant.ExpiresAt is not null && grant.ExpiresAt <= DateTimeOffset.UtcNow;
            var state = revoked ? "REVOKED" : expired ? "EXPIRED" : "ACTIVE";
            var item = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            item.ColumnDefinitions.Add(new ColumnDefinition());
            item.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            item.Children.Add(BodyText(
                $"{grant.PaperTitle}  ·  {grant.RecipientName} ({grant.RecipientEmail})  ·  {state}\n" +
                $"Granted {grant.IssuedAt.ToLocalTime():g}  ·  Expires {grant.ExpiresAt?.ToLocalTime().ToString("g") ?? "Never"}\n" +
                $"Grant ID {grant.GrantId}"));
            if (!revoked && !expired)
            {
                var revoke = SmallAction("Revoke access", "#FDECEC", "#A62525");
                revoke.Click += async (_, _) => await RevokeDistributionGrantAsync(grant.GrantId);
                Grid.SetColumn(revoke, 1);
                item.Children.Add(revoke);
            }

            grantList.Children.Add(item);
            grantList.Children.Add(new Border
            {
                Height = 1,
                Margin = new Thickness(0, 0, 0, 10),
                Background = new SolidColorBrush(Color.FromRgb(231, 237, 245))
            });
        }

        ModuleContent.Children.Add(Section($"Recipient access grants ({grants.Count})", grantList));

        var copyList = new StackPanel();
        if (copies.Count == 0)
        {
            copyList.Children.Add(EmptyState("No paper copies have been issued yet."));
        }

        foreach (var copy in copies)
        {
            copyList.Children.Add(BodyText(
                $"{copy.Action.ToUpperInvariant()}  ·  Paper {copy.PaperId}  ·  Recipient {copy.RecipientUserId}\n" +
                $"Copy ID {copy.CopyId}  ·  Issued {copy.IssuedAt.ToLocalTime():g}  ·  SHA-256 {copy.ContentSha256}"));
            copyList.Children.Add(new Border
            {
                Height = 1,
                Margin = new Thickness(0, 8, 0, 8),
                Background = new SolidColorBrush(Color.FromRgb(231, 237, 245))
            });
        }

        ModuleContent.Children.Add(Section($"Issued copy register ({copies.Count})", copyList));
    }

    private async Task RevokeDistributionGrantAsync(string grantId)
    {
        try
        {
            await _api.RevokeDistributionGrantAsync(grantId);
            StatusMessage.Text = "Recipient access revoked.";
            await OpenPageAsync("distribution");
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusMessage.Text = DescribeError(exception, "Could not revoke recipient access.");
        }
    }

    private void RenderOverview()
    {
        DashboardCards.Children.Clear();
        AddCard("SIGNED IN AS", _user?.DisplayName ?? string.Empty);
        AddCard("ROLE", FormatRole(_user?.Role ?? string.Empty));
        AddCard("MFA", _user?.MfaEnabled == true ? "Enabled" : "Not enrolled");
        AddCard("SESSION", _expiresAt?.ToLocalTime().ToString("g") ?? "Active");
        AddInfoPanel("Authentication policy",
            "Password + authenticator code + an approved workstation are required. Sessions expire after 8 hours and are validated by the server on every protected request.");
    }

    private async Task RenderSecurityAsync()
    {
        var session = await _api.GetCurrentSessionAsync();
        AddInfoPanel("Multi-factor authentication",
            session.User.MfaEnabled
                ? "Enabled · Authenticator verification is required at every sign-in."
                : "Not enrolled · You will be required to configure an authenticator at sign-in.");
        AddInfoPanel("Registered workstation",
            $"Verified · {_device.Name}\nDevice ID: {_device.DeviceId}");
        AddInfoPanel("Current session",
            $"Expires: {session.ExpiresAt.ToLocalTime():f}\nThe server revalidates your account, role, device approval, and expiry on each request.");

        var form = new StackPanel();
        var currentPassword = new SecureEntry { Margin = new Thickness(0, 6, 0, 10) };
        var newPassword = new SecureEntry { Margin = new Thickness(0, 6, 0, 10) };
        var confirmPassword = new SecureEntry { Margin = new Thickness(0, 6, 0, 12) };
        var change = new Button
        {
            Content = "Change password",
            Background = (Brush)FindResource("NavyBrush"),
            Foreground = Brushes.White,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        change.Click += async (_, _) =>
        {
            if (newPassword.Value != confirmPassword.Value)
            {
                StatusMessage.Text = "The new passwords do not match.";
                return;
            }

            change.IsEnabled = false;
            try
            {
                await _api.ChangePasswordAsync(currentPassword.Value, newPassword.Value);
                ReturnToLogin("Password changed. Sign in with the new password.");
            }
            catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
            {
                StatusMessage.Text = DescribeError(exception, "Could not change password.");
            }
            finally
            {
                currentPassword.Clear();
                newPassword.Clear();
                confirmPassword.Clear();
                change.IsEnabled = true;
            }
        };
        form.Children.Add(Field("Current password", currentPassword));
        form.Children.Add(Field("New password (14+ characters, letters and numbers)", newPassword));
        form.Children.Add(Field("Confirm new password", confirmPassword));
        form.Children.Add(change);
        ModuleContent.Children.Add(Section("Change password", form));
    }

    private async Task RenderUsersAsync()
    {
        var users = await _api.GetUsersAsync();
        var form = new StackPanel();
        var email = NewTextBox("name@example.org");
        var displayName = NewTextBox("Display name");
        var role = new ComboBox
        {
            Height = 40,
            Margin = new Thickness(0, 6, 0, 10),
            Padding = new Thickness(9),
            ItemsSource = new[] { "setter", "reviewer", "investigator", "admin" },
            SelectedIndex = 0
        };
        var password = new SecureEntry { Margin = new Thickness(0, 6, 0, 12) };
        var create = new Button
        {
            Content = "Create account",
            Background = (Brush)FindResource("NavyBrush"),
            Foreground = Brushes.White,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        create.Click += async (_, _) =>
        {
            create.IsEnabled = false;
            try
            {
                await _api.CreateUserAsync(email.Text, displayName.Text, role.SelectedItem?.ToString() ?? "setter", password.Value);
                password.Clear();
                StatusMessage.Text = "Account created. The user will set up MFA on first sign-in.";
                await OpenPageAsync("users");
            }
            catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
            {
                StatusMessage.Text = DescribeError(exception, "Could not create the account.");
            }
            finally
            {
                create.IsEnabled = true;
            }
        };
        form.Children.Add(Field("Email address", email));
        form.Children.Add(Field("Display name", displayName));
        form.Children.Add(Field("Role", role));
        form.Children.Add(Field("Temporary password (14+ characters, letters and numbers)", password));
        form.Children.Add(create);
        ModuleContent.Children.Add(Section("Add a user", form));
        ModuleContent.Children.Add(Section("Accounts", BuildUsersList(users)));
    }

    private async Task RenderDevicesAsync()
    {
        var devices = await _api.GetDevicesAsync();
        var list = new StackPanel();
        if (devices.Count == 0)
        {
            list.Children.Add(EmptyState("No workstations have been enrolled."));
        }

        foreach (var device in devices)
        {
            var row = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var actions = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var details = new StackPanel();
            details.Children.Add(TitleText(device.Name));
            var policyCheck = device.ComplianceCheckedAt is null
                ? "Never checked"
                : $"Checked {device.ComplianceCheckedAt.Value.ToLocalTime():g}";
            details.Children.Add(BodyText(
                $"{device.UserName}  ·  {device.Status.ToUpperInvariant()}  ·  POLICY {device.ComplianceStatus.ToUpperInvariant()}\n" +
                $"{device.Centre} / {device.Room} / {device.WorkstationId}\n" +
                $"{device.DeviceId}  ·  Enrolled {device.CreatedAt.ToLocalTime():g}\n" +
                $"OS: {device.OperatingSystem}  ·  App control policy: {PolicyState(device.ApplicationControlPolicyDetected)}  ·  System restrictions: {PolicyState(device.SystemRestrictionsConfigured)}\n" +
                policyCheck));
            row.Children.Add(details);

            var assignment = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            var centre = AssignmentInput(device.Centre, "Centre");
            var room = AssignmentInput(device.Room, "Room");
            var workstationId = AssignmentInput(device.WorkstationId, "Workstation ID");
            assignment.Children.Add(centre);
            assignment.Children.Add(room);
            assignment.Children.Add(workstationId);
            var saveAssignment = SmallAction("Save location", "#EAF1FB", "#2355A0");
            saveAssignment.Margin = new Thickness(8, 0, 0, 0);
            saveAssignment.Click += async (_, _) =>
                await AssignWorkstationAsync(device.DeviceId, centre.Text, room.Text, workstationId.Text);
            assignment.Children.Add(saveAssignment);
            actions.Children.Add(assignment);

            var deviceActions = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(0, 8, 0, 0)
            };
            if (device.Status != "approved")
            {
                var approve = SmallAction(device.Status == "revoked" ? "Re-approve" : "Approve", "#E7F5EC", "#176B3A");
                approve.Click += async (_, _) => await ChangeDeviceStatusAsync(device.DeviceId, "approved");
                deviceActions.Children.Add(approve);
            }

            if (device.Status != "revoked")
            {
                var revoke = SmallAction("Revoke", "#FDECEC", "#A62525");
                revoke.Margin = new Thickness(8, 0, 0, 0);
                revoke.Click += async (_, _) => await ChangeDeviceStatusAsync(device.DeviceId, "revoked");
                deviceActions.Children.Add(revoke);
            }

            if (deviceActions.Children.Count > 0)
            {
                actions.Children.Add(deviceActions);
            }

            Grid.SetColumn(actions, 1);
            row.Children.Add(actions);
            list.Children.Add(row);
            list.Children.Add(new Border { Height = 1, Margin = new Thickness(0, 0, 0, 10), Background = new SolidColorBrush(Color.FromRgb(231, 237, 245)) });
        }

        ModuleContent.Children.Add(Section("Registered workstations", list));
    }

    private async Task AssignWorkstationAsync(string deviceId, string centre, string room, string workstationId)
    {
        try
        {
            await _api.AssignWorkstationAsync(deviceId, centre, room, workstationId);
            StatusMessage.Text = "Workstation location saved.";
            await OpenPageAsync("devices");
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusMessage.Text = DescribeError(exception, "Could not save workstation location.");
        }
    }

    private static TextBox AssignmentInput(string value, string label) => new()
    {
        Text = value == "Unassigned" ? string.Empty : value,
        ToolTip = label,
        Width = 140,
        Height = 34,
        Margin = new Thickness(0, 0, 8, 0),
        Padding = new Thickness(8, 5, 8, 5),
        VerticalContentAlignment = VerticalAlignment.Center
    };

    private static string PolicyState(bool enabled) => enabled ? "Detected" : "Missing";

    private StackPanel BuildUsersList(IReadOnlyList<UserSummary> users)
    {
        var list = new StackPanel();
        if (users.Count == 0)
        {
            list.Children.Add(EmptyState("No user accounts found."));
        }

        foreach (var user in users)
        {
            var row = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var details = new StackPanel();
            details.Children.Add(TitleText(user.DisplayName));
            details.Children.Add(BodyText($"{user.Email}\n{FormatRole(user.Role)}  ·  {user.Status.ToUpperInvariant()}  ·  MFA {(user.MfaEnabled ? "enabled" : "not enrolled")}"));
            row.Children.Add(details);
            if (user.UserId != _user?.UserId)
            {
                var toggle = SmallAction(user.Status == "active" ? "Disable" : "Enable",
                    user.Status == "active" ? "#FDECEC" : "#E7F5EC",
                    user.Status == "active" ? "#A62525" : "#176B3A");
                toggle.Click += async (_, _) =>
                {
                    toggle.IsEnabled = false;
                    try
                    {
                        await _api.SetUserStatusAsync(user.UserId, user.Status == "active" ? "disabled" : "active");
                        await OpenPageAsync("users");
                    }
                    catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
                    {
                        StatusMessage.Text = DescribeError(exception, "Could not update the account.");
                    }
                    finally
                    {
                        toggle.IsEnabled = true;
                    }
                };
                actions.Children.Add(toggle);

                var rolePicker = new ComboBox
                {
                    Width = 112,
                    Height = 33,
                    Margin = new Thickness(8, 0, 0, 0),
                    Padding = new Thickness(5),
                    ItemsSource = new[] { "admin", "setter", "reviewer", "investigator" },
                    SelectedItem = user.Role
                };
                var saveRole = SmallAction("Save role", "#EAF0F7", "#173B67");
                saveRole.Margin = new Thickness(6, 0, 0, 0);
                saveRole.Click += async (_, _) =>
                {
                    saveRole.IsEnabled = false;
                    try
                    {
                        await _api.SetUserRoleAsync(user.UserId, rolePicker.SelectedItem?.ToString() ?? user.Role);
                        StatusMessage.Text = "Role updated. The user's existing sessions were revoked.";
                        await OpenPageAsync("users");
                    }
                    catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
                    {
                        StatusMessage.Text = DescribeError(exception, "Could not update the role.");
                    }
                    finally
                    {
                        saveRole.IsEnabled = true;
                    }
                };
                actions.Children.Add(rolePicker);
                actions.Children.Add(saveRole);
            }

            if (user.MfaEnabled && user.UserId != _user?.UserId)
            {
                var resetMfa = SmallAction("Reset MFA", "#FFF4DB", "#845B00");
                resetMfa.Margin = new Thickness(8, 0, 0, 0);
                resetMfa.Click += async (_, _) =>
                {
                    var confirm = MessageBox.Show(
                        this,
                        $"Reset MFA for {user.DisplayName}? This signs the user out everywhere; they must enroll an authenticator again.",
                        "Confirm MFA reset",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                    if (confirm != MessageBoxResult.Yes)
                    {
                        return;
                    }

                    try
                    {
                        await _api.ResetMfaAsync(user.UserId);
                        StatusMessage.Text = "MFA reset. The user must enroll again at next sign-in.";
                        await OpenPageAsync("users");
                    }
                    catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
                    {
                        StatusMessage.Text = DescribeError(exception, "Could not reset MFA.");
                    }
                };
                actions.Children.Add(resetMfa);
            }

            if (actions.Children.Count > 0)
            {
                Grid.SetColumn(actions, 1);
                row.Children.Add(actions);
            }

            list.Children.Add(row);
            list.Children.Add(new Border { Height = 1, Margin = new Thickness(0, 0, 0, 10), Background = new SolidColorBrush(Color.FromRgb(231, 237, 245)) });
        }

        return list;
    }

    private async Task ChangeDeviceStatusAsync(string deviceId, string status)
    {
        try
        {
            await _api.SetDeviceStatusAsync(deviceId, status);
            StatusMessage.Text = $"Workstation {status}.";
            await OpenPageAsync("devices");
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusMessage.Text = DescribeError(exception, "Could not update workstation.");
        }
    }

    private async void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        if (_paperWorkspace is not null && !await _paperWorkspace.SavePendingChangesAsync())
        {
            if (MessageBox.Show(this,
                    "The latest paper edits could not be saved. Sign out and discard the unsaved changes?",
                    "Unsaved paper changes", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }
        }

        try
        {
            await _api.LogoutAsync();
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            StatusMessage.Text = $"The server did not confirm sign-out: {exception.Message}";
        }

        ReturnToLogin("You have signed out.");
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) =>
        await OpenPageAsync(_activePage);

    private async void SessionTimer_Tick(object? sender, EventArgs e)
    {
        if (_checkingSession || _user is null)
        {
            return;
        }

        if (_expiresAt <= DateTimeOffset.UtcNow)
        {
            ReturnToLogin("Your session expired. Sign in again.");
            return;
        }

        _checkingSession = true;
        try
        {
            var current = await _api.GetCurrentSessionAsync();
            _user = current.User;
            _expiresAt = current.ExpiresAt;
            UpdateSessionExpiryLabel();
        }
        catch (SessionExpiredException exception)
        {
            ReturnToLogin(exception.Message);
        }
        catch (HttpRequestException)
        {
            StatusMessage.Text = "Session status could not be checked; protected actions remain server-validated.";
        }
        finally
        {
            _checkingSession = false;
        }
    }

    private void ReturnToLogin(string message)
    {
        _sessionTimer.Stop();
        _paperWorkspace?.ClearSensitiveState();
        _paperWorkspace = null;
        _user = null;
        _expiresAt = null;
        ApplicationScreen.Visibility = Visibility.Collapsed;
        LoginScreen.Visibility = Visibility.Visible;
        ResetLogin();
        LoginMessage.Text = message;
    }

    private void UpdateSessionExpiryLabel()
    {
        SessionExpiryLabel.Text = _expiresAt is null
            ? string.Empty
            : $"Session expires {_expiresAt.Value.ToLocalTime():t}";
    }

    private void UpdateNavigationSelection(string selectedKey)
    {
        foreach (var (key, item) in _navigation)
        {
            var selected = key == selectedKey;
            item.Button.Background = selected
                ? new SolidColorBrush(Color.FromRgb(36, 74, 118))
                : Brushes.Transparent;
            item.Button.BorderBrush = selected
                ? new SolidColorBrush(Color.FromRgb(57, 184, 154))
                : Brushes.Transparent;
            item.Button.BorderThickness = new Thickness(selected ? 2 : 1, 1, 1, 1);
            item.Button.Foreground = Brushes.White;
        }
    }

    private void AddCard(string label, string value)
    {
        var card = new Border
        {
            Width = 220,
            Margin = new Thickness(0, 0, 14, 14),
            Padding = new Thickness(20),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(225, 232, 240)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(11)
        };
        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = value,
            FontSize = 21,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("InkBrush"),
            TextWrapping = TextWrapping.Wrap
        });
        stack.Children.Add(new TextBlock
        {
            Text = label,
            Margin = new Thickness(0, 6, 0, 0),
            FontSize = 10,
            FontWeight = FontWeights.Bold,
            Foreground = (Brush)FindResource("MutedBrush")
        });
        card.Child = stack;
        DashboardCards.Children.Add(card);
    }

    private void AddInfoPanel(string title, string message)
    {
        var stack = new StackPanel();
        stack.Children.Add(TitleText(title));
        stack.Children.Add(BodyText(message));
        ModuleContent.Children.Add(Section(title, stack));
    }

    private static Border Section(string title, UIElement content)
    {
        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = title,
            Margin = new Thickness(0, 0, 0, 16),
            FontSize = 17,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(23, 43, 77))
        });
        stack.Children.Add(content);
        return new Border
        {
            Margin = new Thickness(0, 0, 0, 18),
            Padding = new Thickness(22),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(225, 232, 240)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(11),
            Child = stack
        };
    }

    private static UIElement Field(string label, UIElement input)
    {
        var stack = new StackPanel();
        stack.Children.Add(new TextBlock { Text = label, FontSize = 12, FontWeight = FontWeights.SemiBold });
        stack.Children.Add(input);
        return stack;
    }

    private static TextBox NewTextBox(string placeholder)
    {
        var input = new TextBox
        {
            Height = 40,
            Margin = new Thickness(0, 6, 0, 10),
            VerticalContentAlignment = VerticalAlignment.Center
        };
        input.Tag = placeholder;
        input.ToolTip = placeholder;
        return input;
    }

    private static TextBlock TitleText(string text) => new()
    {
        Text = text,
        FontSize = 14,
        FontWeight = FontWeights.SemiBold,
        Foreground = new SolidColorBrush(Color.FromRgb(23, 43, 77))
    };

    private static TextBlock BodyText(string text) => new()
    {
        Text = text,
        Margin = new Thickness(0, 4, 12, 0),
        FontSize = 12,
        Foreground = new SolidColorBrush(Color.FromRgb(104, 119, 140)),
        TextWrapping = TextWrapping.Wrap
    };

    private static TextBlock EmptyState(string text) => new()
    {
        Text = text,
        Foreground = new SolidColorBrush(Color.FromRgb(104, 119, 140)),
        Margin = new Thickness(0, 0, 0, 10)
    };

    private static Button SmallAction(string text, string background, string foreground) => new()
    {
        Content = text,
        Padding = new Thickness(10, 7, 10, 7),
        Margin = new Thickness(0, 2, 0, 2),
        Background = (Brush)new BrushConverter().ConvertFromString(background)!,
        Foreground = (Brush)new BrushConverter().ConvertFromString(foreground)!,
        FontSize = 11
    };

    private void SetBusy(bool busy)
    {
        LoginButton.IsEnabled = !busy;
        BackButton.IsEnabled = !busy;
        RefreshButton.IsEnabled = !busy;
        Mouse.OverrideCursor = busy ? Cursors.Wait : null;
    }

    private static string DescribeError(Exception exception, string networkMessage) =>
        exception is HttpRequestException
            ? networkMessage
            : exception.Message;

    private static string FormatRole(string role) =>
        role switch
        {
            "admin" => "Administrator",
            "setter" => "Paper Setter",
            "reviewer" => "Reviewer",
            "investigator" => "Investigator",
            _ => role
        };

    protected override void OnClosed(EventArgs e)
    {
        _sessionTimer.Stop();
        _api.Dispose();
        base.OnClosed(e);
    }

    private sealed record NavigationItem(string Title, Button Button);
}
