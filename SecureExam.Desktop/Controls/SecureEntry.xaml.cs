using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace SecureExam.Desktop.Controls;

public partial class SecureEntry : UserControl
{
    private readonly StringBuilder _value = new();

    public SecureEntry()
    {
        InitializeComponent();
        PreviewKeyDown += OnPreviewKeyDown;
        PreviewTextInput += OnPreviewTextInput;
        GotKeyboardFocus += (_, _) => Frame.BorderBrush = (System.Windows.Media.Brush)FindResource("NavyBrush");
        LostKeyboardFocus += (_, _) => Frame.BorderBrush = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(215, 223, 233));
        MouseLeftButtonDown += (_, args) =>
        {
            Focus();
            args.Handled = true;
        };
    }

    public string Value => _value.ToString();

    public void Clear()
    {
        _value.Clear();
        UpdateMask();
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Back)
        {
            if (_value.Length > 0)
            {
                _value.Length--;
                UpdateMask();
            }

            e.Handled = true;
            return;
        }

        if (e.Key == Key.V && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
        {
            try
            {
                _value.Append(Clipboard.GetText());
                UpdateMask();
            }
            catch (System.Runtime.InteropServices.ExternalException)
            {
            }

            e.Handled = true;
        }
    }

    private void OnPreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        _value.Append(e.Text);
        UpdateMask();
        e.Handled = true;
    }

    private void UpdateMask() => Mask.Text = new string('*', _value.Length);
}
