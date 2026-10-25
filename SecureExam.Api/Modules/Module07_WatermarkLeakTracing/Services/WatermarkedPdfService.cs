using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SecureExam.Api.Models;

namespace SecureExam.Api.Services;

internal sealed class WatermarkedPdfService
{
    public byte[] Create(PaperSummary paper, string copyId, string recipientName, string recipientEmail)
    {
        var watermark = $"CONTROLLED COPY  |  {recipientName}  |  {recipientEmail}  |  {copyId}";
        return Document.Create(document =>
        {
            document.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(48);
                page.DefaultTextStyle(style => style.FontSize(10));
                page.Background()
                    .AlignCenter()
                    .AlignMiddle()
                    .Rotate(-35)
                    .Text(watermark)
                    .FontSize(19)
                    .FontColor(Colors.Grey.Lighten2);
                page.Header()
                    .PaddingBottom(10)
                    .BorderBottom(1)
                    .BorderColor(Colors.Grey.Lighten2)
                    .Text($"CONTROLLED COPY · {copyId}")
                    .FontSize(9)
                    .FontColor(Colors.Red.Medium);
                page.Content().Column(column =>
                {
                    column.Spacing(8);
                    column.Item().Text(paper.Title).FontSize(20).Bold();
                    column.Item().Text($"{paper.Subject} · {paper.ExamCode} · {paper.TotalMarks} marks");
                    column.Item().Text($"Paper version {paper.Version} · Issued to {recipientName} ({recipientEmail})");

                    if (!string.IsNullOrWhiteSpace(paper.Instructions))
                    {
                        column.Item().PaddingTop(10).Text("Instructions").FontSize(13).Bold();
                        column.Item().Text(paper.Instructions);
                    }

                    if (paper.Sections.Count > 0)
                    {
                        column.Item().PaddingTop(10).Text("Sections").FontSize(13).Bold();
                        foreach (var section in paper.Sections)
                        {
                            column.Item().Text($"{section.Name} — {section.Marks} marks");
                        }
                    }

                    if (paper.Content.Paragraphs.Count > 0)
                    {
                        column.Item().PaddingTop(10).Text("Questions").FontSize(13).Bold();
                        foreach (var paragraph in paper.Content.Paragraphs)
                        {
                            var text = string.Concat(paragraph.Runs.Select(run => run.Text));
                            column.Item().Text(string.IsNullOrEmpty(text) ? " " : text);
                        }
                    }
                });
                page.Footer()
                    .AlignCenter()
                    .Text($"Recipient-specific copy · {copyId}");
            });
        }).GeneratePdf();
    }
}
