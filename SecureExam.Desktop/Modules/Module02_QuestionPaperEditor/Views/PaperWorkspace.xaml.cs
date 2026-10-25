using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using SecureExam.Desktop.Models;
using SecureExam.Desktop.Services;

namespace SecureExam.Desktop.Views;

public partial class PaperWorkspace : UserControl
{
    private readonly ApiClient _api;
    private readonly SessionUser _user;
    private readonly DispatcherTimer _saveTimer = new() { Interval = TimeSpan.FromMilliseconds(900) };
    private PaperSummary? _paper;
    private bool _loading;
    private bool _saving;
    private bool _saveAgain;
    private bool _dirty;

    internal PaperWorkspace(ApiClient api, SessionUser user)
    {
        InitializeComponent();
        _api = api;
        _user = user;
        AccessAuditButton.Visibility = _user.Role == "admin" ? Visibility.Visible : Visibility.Collapsed;
        VerifyCopyButton.Visibility = _user.Role is "admin" or "investigator" ? Visibility.Visible : Visibility.Collapsed;
        _saveTimer.Tick += SaveTimer_Tick;
        Unloaded += (_, _) => ClearSensitiveState();
        TitleInput.TextChanged += EditorField_TextChanged;
        SubjectInput.TextChanged += EditorField_TextChanged;
        ExamCodeInput.TextChanged += EditorField_TextChanged;
        TotalMarksInput.TextChanged += EditorField_TextChanged;
        SectionsInput.TextChanged += EditorField_TextChanged;
        InstructionsInput.TextChanged += EditorField_TextChanged;
        _ = LoadPapersAsync();
    }

    private bool CanCreate => _user.Role is "admin" or "setter";
    private bool CanReview => _user.Role is "admin" or "reviewer";
    private bool CanEditPaper => _paper is not null &&
        _paper.Status is "draft" or "changes_requested" &&
        (_user.Role == "admin" || (_user.Role == "setter" && _paper.OwnerId == _user.UserId));

    private async Task LoadPapersAsync()
    {
        NewPaperButton.Visibility = CanCreate ? Visibility.Visible : Visibility.Collapsed;
        ListMessage.Text = "Loading papers…";
        try
        {
            var papers = await _api.GetPapersAsync();
            PaperList.Children.Clear();
            if (papers.Count == 0)
            {
                PaperList.Children.Add(EmptyState("No papers are available to your account yet."));
            }
            else
            {
                foreach (var paper in papers)
                {
                    PaperList.Children.Add(BuildPaperRow(paper));
                }
            }

            ListMessage.Text = $"{papers.Count} paper{(papers.Count == 1 ? string.Empty : "s")} available. Drafts are saved automatically.";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            ListMessage.Text = DescribeError(exception, "Could not load papers.");
        }
    }

    private UIElement BuildPaperRow(PaperSummary paper)
    {
        var border = new Border
        {
            Margin = new Thickness(0, 0, 0, 10),
            Padding = new Thickness(16),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(227, 233, 240)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8)
        };
        var row = new Grid();
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var details = new StackPanel();
        details.Children.Add(new TextBlock
        {
            Text = paper.Title,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)FindResource("InkBrush")
        });
        details.Children.Add(new TextBlock
        {
            Margin = new Thickness(0, 5, 0, 0),
            Text = $"{paper.Subject}  ·  {paper.ExamCode}  ·  {paper.TotalMarks} marks",
            Foreground = (Brush)FindResource("MutedBrush")
        });
        details.Children.Add(new TextBlock
        {
            Margin = new Thickness(0, 4, 0, 0),
            Text = $"{FormatStatus(paper.Status, paper.ReviewerDecision)}  ·  Version {paper.Version}  ·  Updated {paper.UpdatedAt.ToLocalTime():g}" +
                   (_user.Role == "admin" || _user.Role == "reviewer" ? $"  ·  {paper.OwnerName}" : string.Empty),
            FontSize = 11,
            Foreground = (Brush)FindResource("MutedBrush")
        });
        row.Children.Add(details);
        var open = new Button
        {
            Content = CanEditPaperFor(paper) ? "Open editor" : "View paper",
            Margin = new Thickness(14, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Background = (Brush)FindResource("NavyBrush"),
            Foreground = Brushes.White,
            Tag = paper.PaperId
        };
        open.Click += async (_, _) => await OpenPaperAsync(paper.PaperId);
        Grid.SetColumn(open, 1);
        row.Children.Add(open);
        border.Child = row;
        return border;
    }

    private bool CanEditPaperFor(PaperSummary paper) =>
        paper.Status is "draft" or "changes_requested" &&
        (_user.Role == "admin" || (_user.Role == "setter" && paper.OwnerId == _user.UserId));

    private async void NewPaperButton_Click(object sender, RoutedEventArgs e)
    {
        var now = DateTimeOffset.Now;
        var request = new PaperDraftRequest
        {
            Title = "Untitled question paper",
            Subject = "New subject",
            ExamCode = $"DRAFT-{now:yyyyMMdd-HHmmss}",
            Sections = new[] { new PaperSection { Name = "Section A", Marks = 1 } },
            TotalMarks = 1,
            Instructions = string.Empty,
            Content = EmptyDocument()
        };

        NewPaperButton.IsEnabled = false;
        try
        {
            _paper = await _api.CreatePaperAsync(request);
            ShowEditor(_paper);
            SaveStateLabel.Text = "Draft created · changes save automatically.";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            ListMessage.Text = DescribeError(exception, "Could not create a paper draft.");
        }
        finally
        {
            NewPaperButton.IsEnabled = true;
        }
    }

    private async Task OpenPaperAsync(string paperId)
    {
        ListMessage.Text = "Opening paper…";
        try
        {
            _paper = await _api.GetPaperAsync(paperId);
            ShowEditor(_paper);
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            ListMessage.Text = DescribeError(exception, "Could not open paper.");
            await LoadPapersAsync();
        }
    }

    private void ShowEditor(PaperSummary paper)
    {
        _saveTimer.Stop();
        _paper = paper;
        _loading = true;
        try
        {
            ListPanel.Visibility = Visibility.Collapsed;
            EditorPanel.Visibility = Visibility.Visible;
            EditorTitle.Text = paper.Title;
            PaperStateLabel.Text = $"{FormatStatus(paper.Status, paper.ReviewerDecision)}  ·  Version {paper.Version}";
            TitleInput.Text = paper.Title;
            SubjectInput.Text = paper.Subject;
            ExamCodeInput.Text = paper.ExamCode;
            TotalMarksInput.Text = paper.TotalMarks.ToString(CultureInfo.InvariantCulture);
            SectionsInput.Text = string.Join(Environment.NewLine,
                paper.Sections.Select(section => $"{section.Name} | {section.Marks}"));
            InstructionsInput.Text = paper.Instructions;
            RenderDocument(paper.Content);

            var editable = CanEditPaper;
            TitleInput.IsReadOnly = !editable;
            SubjectInput.IsReadOnly = !editable;
            ExamCodeInput.IsReadOnly = !editable;
            TotalMarksInput.IsReadOnly = !editable;
            SectionsInput.IsReadOnly = !editable;
            InstructionsInput.IsReadOnly = !editable;
            QuestionEditor.IsReadOnly = !editable;
            BoldButton.IsEnabled = editable;
            ItalicButton.IsEnabled = editable;
            UnderlineButton.IsEnabled = editable;
            SaveButton.Visibility = editable ? Visibility.Visible : Visibility.Collapsed;
            SubmitButton.Visibility = editable ? Visibility.Visible : Visibility.Collapsed;
            ApproveButton.Visibility = CanReview && paper.Status == "submitted" ? Visibility.Visible : Visibility.Collapsed;
            RequestChangesButton.Visibility = CanReview && paper.Status == "submitted" ? Visibility.Visible : Visibility.Collapsed;
            RejectButton.Visibility = CanReview && paper.Status == "submitted" ? Visibility.Visible : Visibility.Collapsed;
            ExportButton.Visibility = paper.Status == "approved" ? Visibility.Visible : Visibility.Collapsed;
            PrintButton.Visibility = paper.Status == "approved" ? Visibility.Visible : Visibility.Collapsed;
            SaveStateLabel.Text = editable
                ? $"Draft saved · Version {paper.Version} · autosave is on."
                : paper.Status == "approved"
                    ? $"Approved paper · read-only · Version {paper.Version}" +
                      (paper.IssuedCopyId is null ? string.Empty : $" · Copy {paper.IssuedCopyId}")
                    : $"Submitted paper · read-only · Version {paper.Version}" +
                      (paper.ReviewerComment is null ? string.Empty : $" · Reviewer: {paper.ReviewerComment}");
            _dirty = false;
        }
        finally
        {
            _loading = false;
        }
    }

    private void EditorField_TextChanged(object sender, TextChangedEventArgs e) => MarkDirty();

    private void QuestionEditor_TextChanged(object sender, TextChangedEventArgs e) => MarkDirty();

    private void MarkDirty()
    {
        if (_loading || !CanEditPaper)
        {
            return;
        }

        _dirty = true;
        SaveStateLabel.Text = "Unsaved changes · saving automatically…";
        _saveTimer.Stop();
        _saveTimer.Start();
    }

    private async void SaveTimer_Tick(object? sender, EventArgs e)
    {
        _saveTimer.Stop();
        await SaveDraftAsync();
    }

    private async void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        _saveTimer.Stop();
        await SaveDraftAsync();
    }

    private async Task SaveDraftAsync()
    {
        if (!_dirty || _paper is null || !CanEditPaper)
        {
            return;
        }

        if (_saving)
        {
            _saveAgain = true;
            return;
        }

        PaperDraftRequest request;
        try
        {
            request = BuildRequest();
        }
        catch (ArgumentException exception)
        {
            SaveStateLabel.Text = exception.Message;
            return;
        }

        _saving = true;
        _dirty = false;
        var saveFailed = false;
        try
        {
            _paper = await _api.SavePaperAsync(_paper.PaperId, request);
            EditorTitle.Text = _paper.Title;
            PaperStateLabel.Text = $"{FormatStatus(_paper.Status, _paper.ReviewerDecision)}  ·  Version {_paper.Version}";
            SaveStateLabel.Text = $"All changes saved · Version {_paper.Version} · {_paper.UpdatedAt.ToLocalTime():t}";
        }
        catch (SessionExpiredException exception)
        {
            saveFailed = true;
            SaveStateLabel.Text = exception.Message;
            IsEnabled = false;
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            saveFailed = true;
            _dirty = true;
            SaveStateLabel.Text = DescribeError(exception, "Autosave failed. Your current editor contents are still on screen.");
        }
        finally
        {
            _saving = false;
            if (_saveAgain || (_dirty && !saveFailed))
            {
                _saveAgain = false;
                _saveTimer.Stop();
                _saveTimer.Start();
            }
        }
    }

    private PaperDraftRequest BuildRequest()
    {
        if (!int.TryParse(TotalMarksInput.Text, NumberStyles.None, CultureInfo.InvariantCulture, out var totalMarks))
        {
            throw new ArgumentException("Enter a valid total mark value.");
        }

        var sections = new List<PaperSection>();
        foreach (var line in SectionsInput.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Split('|', 2, StringSplitOptions.TrimEntries);
            if (fields.Length != 2 ||
                !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var sectionMarks))
            {
                throw new ArgumentException("Enter each section as: Section A | 20");
            }

            sections.Add(new PaperSection { Name = fields[0], Marks = sectionMarks });
        }

        if (sections.Count == 0 || sections.Any(section => string.IsNullOrWhiteSpace(section.Name) || section.Marks < 1))
        {
            throw new ArgumentException("Add at least one section and give each section positive marks.");
        }

        if (sections.Sum(section => (long)section.Marks) != totalMarks)
        {
            throw new ArgumentException("Section marks must add up to total marks before the draft can be saved.");
        }

        var title = TitleInput.Text.Trim();
        var subject = SubjectInput.Text.Trim();
        var examCode = ExamCodeInput.Text.Trim();
        if (title.Length == 0 || subject.Length == 0 || examCode.Length == 0)
        {
            throw new ArgumentException("Paper title, subject, and exam code are required.");
        }

        return new PaperDraftRequest
        {
            Title = title,
            Subject = subject,
            ExamCode = examCode,
            Sections = sections,
            TotalMarks = totalMarks,
            Instructions = InstructionsInput.Text,
            Content = CaptureDocument()
        };
    }

    private PaperDocument CaptureDocument()
    {
        var paragraphs = new List<PaperParagraph>();
        foreach (var block in QuestionEditor.Document.Blocks)
        {
            if (block is not Paragraph paragraph)
            {
                continue;
            }

            var runs = new List<PaperRun>();
            CaptureInlines(paragraph.Inlines, runs, false, false, false);
            if (runs.Count == 0)
            {
                runs.Add(new PaperRun { Text = string.Empty });
            }

            paragraphs.Add(new PaperParagraph { Runs = runs });
        }

        if (paragraphs.Count == 0)
        {
            paragraphs.Add(new PaperParagraph { Runs = new[] { new PaperRun { Text = string.Empty } } });
        }

        return new PaperDocument { Paragraphs = paragraphs };
    }

    private static void CaptureInlines(
        InlineCollection inlines,
        ICollection<PaperRun> output,
        bool bold,
        bool italic,
        bool underline)
    {
        foreach (var inline in inlines)
        {
            switch (inline)
            {
                case Run run:
                    output.Add(new PaperRun
                    {
                        Text = run.Text,
                        Bold = bold,
                        Italic = italic,
                        Underline = underline
                    });
                    break;
                case LineBreak:
                    output.Add(new PaperRun { Text = "\n", Bold = bold, Italic = italic, Underline = underline });
                    break;
                case Bold boldSpan:
                    CaptureInlines(boldSpan.Inlines, output, true, italic, underline);
                    break;
                case Italic italicSpan:
                    CaptureInlines(italicSpan.Inlines, output, bold, true, underline);
                    break;
                case Underline underlineSpan:
                    CaptureInlines(underlineSpan.Inlines, output, bold, italic, true);
                    break;
                case Span span:
                    CaptureInlines(span.Inlines, output, bold, italic, underline);
                    break;
            }
        }
    }

    private void RenderDocument(PaperDocument document)
    {
        var flow = new FlowDocument();
        foreach (var item in document.Paragraphs)
        {
            var paragraph = new Paragraph();
            foreach (var itemRun in item.Runs)
            {
                Inline inline = new Run(itemRun.Text);
                if (itemRun.Underline)
                {
                    inline = new Underline(inline);
                }

                if (itemRun.Italic)
                {
                    inline = new Italic(inline);
                }

                if (itemRun.Bold)
                {
                    inline = new Bold(inline);
                }

                paragraph.Inlines.Add(inline);
            }

            flow.Blocks.Add(paragraph);
        }

        if (flow.Blocks.Count == 0)
        {
            flow.Blocks.Add(new Paragraph());
        }

        QuestionEditor.Document = flow;
    }

    private async void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_paper is null || _paper.Status != "approved")
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Export recipient-watermarked PDF",
            FileName = $"{SafeFileName(_paper.ExamCode)}-controlled-copy.pdf",
            DefaultExt = ".pdf",
            Filter = "PDF document (*.pdf)|*.pdf",
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true)
        {
            return;
        }

        if (MessageBox.Show(Window.GetWindow(this),
                "A recipient-specific watermarked PDF will be saved at the location you choose. The issuance and PDF fingerprint will be recorded for leak tracing.",
                "Confirm controlled export", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK)
        {
            return;
        }

        ExportButton.IsEnabled = false;
        try
        {
            var copy = await _api.GetWatermarkedCopyAsync(_paper.PaperId);
            await File.WriteAllBytesAsync(dialog.FileName, copy.Pdf);
            SaveStateLabel.Text = $"Watermarked PDF saved · Copy ID {copy.CopyId} · SHA-256 {copy.FingerprintSha256}";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            SaveStateLabel.Text = DescribeError(exception, "The approved paper could not be exported.");
        }
        finally
        {
            ExportButton.IsEnabled = true;
        }
    }

    private async void VerifyCopyButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select a recovered PDF to verify",
            Filter = "PDF document (*.pdf)|*.pdf",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true)
        {
            return;
        }

        VerifyCopyButton.IsEnabled = false;
        try
        {
            var fileInfo = new FileInfo(dialog.FileName);
            if (fileInfo.Length is <= 0 or > 25 * 1024 * 1024)
            {
                throw new IOException("Select a non-empty PDF no larger than 25 MB.");
            }

            var pdf = await File.ReadAllBytesAsync(dialog.FileName);
            var match = await _api.VerifyRecoveredCopyAsync(pdf);
            if (match.MatchFound)
            {
                var issuedAt = match.IssuedAt?.ToLocalTime().ToString("g") ?? "unknown time";
                ListMessage.Text =
                    $"MATCH FOUND · Copy {match.CopyId} · {match.PaperTitle} (version {match.PaperVersion}) · " +
                    $"Recipient {match.RecipientName} ({match.RecipientEmail}) · Issued {issuedAt} · SHA-256 {match.FingerprintSha256}";
            }
            else
            {
                ListMessage.Text =
                    $"No exact issued-PDF fingerprint matched this file. SHA-256: {match.FingerprintSha256}. " +
                    "Scanned or modified copies are not identified by this exact-file verifier.";
            }
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            ListMessage.Text = DescribeError(exception, "Could not verify the recovered PDF.");
        }
        finally
        {
            VerifyCopyButton.IsEnabled = true;
        }
    }

    private async void PrintButton_Click(object sender, RoutedEventArgs e)
    {
        if (_paper is null || _paper.Status != "approved")
        {
            return;
        }

        PrintButton.IsEnabled = false;
        try
        {
            var dialog = new PrintDialog();
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            if (MessageBox.Show(Window.GetWindow(this),
                    "Printing this approved paper will be recorded in the access audit. Keep printed copies physically secure.",
                    "Confirm controlled printing", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK)
            {
                return;
            }

            var access = await _api.AuthorizePaperAccessAsync(_paper.PaperId, "print");
            VerifyIntegrity(access);
            var printDocument = (IDocumentPaginatorSource)BuildPrintDocument(
                access.Paper, access.IssuedCopyId, _user.DisplayName);
            dialog.PrintDocument(printDocument.DocumentPaginator,
                $"CONTROLLED COPY {access.IssuedCopyId} - {access.Paper.Title}");
            SaveStateLabel.Text = $"Print request recorded · Copy ID {access.IssuedCopyId} · SHA-256 {access.IntegritySha256}";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException or InvalidOperationException or System.ComponentModel.Win32Exception or System.Printing.PrintQueueException or System.Printing.PrintSystemException)
        {
            SaveStateLabel.Text = DescribeError(exception, "The approved paper could not be sent to the printer.");
        }
        finally
        {
            PrintButton.IsEnabled = true;
        }
    }

    private async void AccessAuditButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var events = await _api.GetPaperAccessEventsAsync();
            PaperList.Children.Clear();
            if (events.Count == 0)
            {
                PaperList.Children.Add(EmptyState("No export or print requests have been recorded."));
            }

            foreach (var item in events)
            {
                var details = new StackPanel();
                details.Children.Add(new TextBlock
                {
                    Text = $"{item.Action.ToUpperInvariant()}  ·  {item.PaperTitle}",
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("InkBrush")
                });
                details.Children.Add(new TextBlock
                {
                    Margin = new Thickness(0, 4, 0, 0),
                    Text = $"{item.UserName}  ·  {item.OccurredAt.ToLocalTime():g}  ·  Paper {item.PaperId}",
                    Foreground = (Brush)FindResource("MutedBrush"),
                    TextWrapping = TextWrapping.Wrap
                });
                details.Children.Add(new TextBlock
                {
                    Margin = new Thickness(0, 4, 0, 0),
                    Text = $"Content SHA-256: {item.ContentSha256}",
                    FontSize = 10,
                    Foreground = (Brush)FindResource("MutedBrush"),
                    TextWrapping = TextWrapping.Wrap
                });
                PaperList.Children.Add(new Border
                {
                    Margin = new Thickness(0, 0, 0, 8),
                    Padding = new Thickness(14),
                    Background = Brushes.White,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(227, 233, 240)),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(7),
                    Child = details
                });
            }

            ListMessage.Text = $"Showing the latest {events.Count} export/print access events.";
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            ListMessage.Text = DescribeError(exception, "Could not load document access audit.");
        }
    }

    private static void VerifyIntegrity(PaperAccessResult access)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                title = access.Paper.Title,
                subject = access.Paper.Subject,
                examCode = access.Paper.ExamCode,
                sections = access.Paper.Sections,
                totalMarks = access.Paper.TotalMarks,
                instructions = access.Paper.Instructions,
                content = access.Paper.Content
            },
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        var actual = Convert.ToHexString(SHA256.HashData(bytes));
        var expectedBytes = Encoding.ASCII.GetBytes(access.IntegritySha256);
        var actualBytes = Encoding.ASCII.GetBytes(actual);
        if (expectedBytes.Length != actualBytes.Length ||
            !CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes))
        {
            throw new ApiRequestException("Paper content integrity check failed; export and printing were blocked.");
        }
    }

    private static FlowDocument BuildPrintDocument(PaperSummary paper, string copyId, string issuedTo)
    {
        var document = new FlowDocument
        {
            PagePadding = new Thickness(60),
            ColumnWidth = 1000
        };
        document.Blocks.Add(new Paragraph(new Run($"CONTROLLED COPY · Copy ID {copyId} · Handle according to examination policy"))
        {
            FontSize = 10,
            FontWeight = FontWeights.Bold,
            Foreground = Brushes.DarkRed,
            TextAlignment = TextAlignment.Center
        });
        document.Blocks.Add(new Paragraph(new Run(paper.Title))
        {
            FontSize = 22,
            FontWeight = FontWeights.Bold,
            TextAlignment = TextAlignment.Center
        });
        document.Blocks.Add(new Paragraph(new Run($"{paper.Subject}  ·  {paper.ExamCode}  ·  {paper.TotalMarks} marks"))
        {
            TextAlignment = TextAlignment.Center,
            Margin = new Thickness(0, 0, 0, 18)
        });
        document.Blocks.Add(new Paragraph(new Run("Instructions"))
        {
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 8, 0, 2)
        });
        document.Blocks.Add(new Paragraph(new Run(paper.Instructions)));
        foreach (var section in paper.Sections)
        {
            document.Blocks.Add(new Paragraph(new Run($"{section.Name} — {section.Marks} marks"))
            {
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 12, 0, 4)
            });
        }

        foreach (var item in paper.Content.Paragraphs)
        {
            var paragraph = new Paragraph();
            foreach (var run in item.Runs)
            {
                Inline inline = new Run(run.Text);
                if (run.Underline) inline = new Underline(inline);
                if (run.Italic) inline = new Italic(inline);
                if (run.Bold) inline = new Bold(inline);
                paragraph.Inlines.Add(inline);
            }

            document.Blocks.Add(paragraph);
        }

        document.Blocks.Add(new Paragraph(new Run($"Paper {paper.ExamCode} · Version {paper.Version} · Copy ID {copyId} · Issued to {issuedTo} · {DateTimeOffset.Now.ToLocalTime():g}"))
        {
            FontSize = 9,
            Foreground = Brushes.Gray,
            Margin = new Thickness(0, 20, 0, 0)
        });
        return document;
    }

    private static string SafeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var safe = new string(value.Select(character => invalid.Contains(character) ? '_' : character).ToArray()).Trim();
        return string.IsNullOrWhiteSpace(safe) ? "question-paper" : safe;
    }

    internal void ClearSensitiveState()
    {
        _saveTimer.Stop();
        _dirty = false;
        _loading = true;
        _paper = null;
        PaperList.Children.Clear();
        TitleInput.Clear();
        SubjectInput.Clear();
        ExamCodeInput.Clear();
        TotalMarksInput.Clear();
        SectionsInput.Clear();
        InstructionsInput.Clear();
        QuestionEditor.Document = new FlowDocument(new Paragraph());
        _loading = false;
    }

    internal async Task<bool> SavePendingChangesAsync()
    {
        if (!_dirty)
        {
            return true;
        }

        _saveTimer.Stop();
        await SaveDraftAsync();
        return !_dirty;
    }

    private async void VersionsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_paper is null)
        {
            return;
        }

        try
        {
            var versions = await _api.GetPaperVersionsAsync(_paper.PaperId);
            var message = versions.Count == 0
                ? "No version history is available."
                : string.Join(Environment.NewLine, versions.Select(version =>
                    $"Version {version.Version} · {version.Action.Replace('_', ' ')} · {version.ChangedBy} · {version.ChangedAt.ToLocalTime():g} · {FormatStatus(version.Paper.Status, version.Paper.ReviewerDecision)} · Copy ID {version.Paper.IssuedCopyId}"));
            MessageBox.Show(Window.GetWindow(this), message, "Paper version history",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            SaveStateLabel.Text = DescribeError(exception, "Could not load version history.");
        }
    }

    private async void SubmitButton_Click(object sender, RoutedEventArgs e)
    {
        if (_paper is null)
        {
            return;
        }

        _saveTimer.Stop();
        await SaveDraftAsync();
        if (_dirty)
        {
            return;
        }

        if (MessageBox.Show(Window.GetWindow(this),
                "Submit this version for review? You will not be able to edit it unless a reviewer requests changes.",
                "Submit paper", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        await TransitionAsync("submit");
    }

    private async void ApproveButton_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(Window.GetWindow(this),
                "Approve this submitted paper? Approved papers become read-only.",
                "Approve paper", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
        {
            await TransitionAsync("approve");
        }
    }

    private async void RequestChangesButton_Click(object sender, RoutedEventArgs e)
    {
        var comment = PromptForReviewComment("Request changes", "Explain what the setter should revise.");
        if (comment is not null)
        {
            await TransitionAsync("request_changes", comment);
        }
    }

    private async void RejectButton_Click(object sender, RoutedEventArgs e)
    {
        var comment = PromptForReviewComment("Reject paper", "Enter the reason for rejecting this submission.");
        if (comment is not null)
        {
            await TransitionAsync("reject", comment);
        }
    }

    private static string? PromptForReviewComment(string title, string prompt)
    {
        var dialog = new Window
        {
            Title = title,
            Width = 460,
            Height = 260,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Owner = Application.Current.MainWindow
        };
        var layout = new StackPanel { Margin = new Thickness(20) };
        layout.Children.Add(new TextBlock { Text = prompt, TextWrapping = TextWrapping.Wrap });
        var comment = new TextBox
        {
            Margin = new Thickness(0, 12, 0, 12),
            Height = 100,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MaxLength = 1000
        };
        layout.Children.Add(comment);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var cancel = new Button { Content = "Cancel", MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
        cancel.Click += (_, _) => dialog.DialogResult = false;
        var confirm = new Button { Content = "Continue", MinWidth = 90, IsDefault = true };
        confirm.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(comment.Text))
            {
                MessageBox.Show(dialog, "Enter a review note before continuing.", title,
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            dialog.DialogResult = true;
        };
        buttons.Children.Add(cancel);
        buttons.Children.Add(confirm);
        layout.Children.Add(buttons);
        dialog.Content = layout;
        return dialog.ShowDialog() == true ? comment.Text.Trim() : null;
    }

    private async Task TransitionAsync(string action, string? comment = null)
    {
        if (_paper is null)
        {
            return;
        }

        SubmitButton.IsEnabled = false;
        ApproveButton.IsEnabled = false;
        RequestChangesButton.IsEnabled = false;
        RejectButton.IsEnabled = false;
        try
        {
            _paper = await _api.TransitionPaperAsync(_paper.PaperId, action, comment);
            ShowEditor(_paper);
        }
        catch (Exception exception) when (exception is ApiRequestException or HttpRequestException or TaskCanceledException)
        {
            SaveStateLabel.Text = DescribeError(exception, "Could not update paper status.");
        }
        finally
        {
            SubmitButton.IsEnabled = true;
            ApproveButton.IsEnabled = true;
            RequestChangesButton.IsEnabled = true;
            RejectButton.IsEnabled = true;
        }
    }

    private async void BackToListButton_Click(object sender, RoutedEventArgs e)
    {
        _saveTimer.Stop();
        if (_dirty)
        {
            await SaveDraftAsync();
            if (_dirty)
            {
                return;
            }
        }

        EditorPanel.Visibility = Visibility.Collapsed;
        ListPanel.Visibility = Visibility.Visible;
        _paper = null;
        await LoadPapersAsync();
    }

    private void BoldButton_Click(object sender, RoutedEventArgs e) =>
        EditingCommands.ToggleBold.Execute(null, QuestionEditor);

    private void ItalicButton_Click(object sender, RoutedEventArgs e) =>
        EditingCommands.ToggleItalic.Execute(null, QuestionEditor);

    private void UnderlineButton_Click(object sender, RoutedEventArgs e) =>
        EditingCommands.ToggleUnderline.Execute(null, QuestionEditor);

    private static PaperDocument EmptyDocument() =>
        new()
        {
            Paragraphs = new[] { new PaperParagraph { Runs = new[] { new PaperRun { Text = string.Empty } } } }
        };

    private static UIElement EmptyState(string message) =>
        new Border
        {
            Padding = new Thickness(18),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(227, 233, 240)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Child = new TextBlock
            {
                Text = message,
                Foreground = new SolidColorBrush(Color.FromRgb(104, 119, 140))
            }
        };

    private static string FormatStatus(string status, string? decision = null) =>
        decision == "reject" ? "Rejected · resubmission required" : status switch
    {
        "changes_requested" => "Changes requested",
        "submitted" => "Awaiting review",
        "approved" => "Approved · read-only",
        _ => "Draft"
    };

    private static string DescribeError(Exception exception, string fallback) =>
        exception is ApiRequestException ? exception.Message : fallback;
}
