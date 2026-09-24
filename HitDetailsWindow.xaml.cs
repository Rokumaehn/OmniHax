using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace OmniHax;

public sealed record RegRow(string Name, string Value);

public sealed record XmmRow(string Name, string V0, string V1, string V2, string V3, string Hex);

public partial class HitDetailsWindow : Window
{
    private readonly HitRecord _record;

    internal HitDetailsWindow(HitRecord record, string instruction, string module)
    {
        InitializeComponent();

        _record = record;

        HeaderText.Text =
            $"{record.TimestampText}   thread {record.ThreadId}   {record.Kind}   value {record.ValueText}\r\n" +
            $"{module}   {record.InstructionPointerText}   {instruction}\r\n" +
            $"effective address {record.Addressing}   (registers are the " +
            $"{(record.Kind == AccessKind.Execute ? "pre-instruction" : "post-instruction")} state)";

        GprList.ItemsSource = record.Gprs.Select(g => new RegRow(g.Name, g.Display)).ToList();
        SegmentList.ItemsSource = record.Segments.Select(g => new RegRow(g.Name, g.Display)).ToList();
        DebugList.ItemsSource = record.DebugRegisters.Select(g => new RegRow(g.Name, g.Display)).ToList();
        FlagsText.Text = $"EFLAGS = {record.EFlagsText}\r\nMXCSR  = {record.MxCsrText}";

        X87List.ItemsSource = record.X87
            .Select((r, i) => new RegRow($"ST{i}", r.Empty ? "(empty)" : $"{r.ValueText}   [0x{r.Hex}]"))
            .ToList();

        UpdateXmm();
    }

    private bool AsDouble => XmmViewCombo.SelectedIndex == 1;

    private void XmmView_Changed(object sender, SelectionChangedEventArgs e) => UpdateXmm();

    private void UpdateXmm()
    {
        if (XmmGrid is null)
            return;

        bool asDouble = AsDouble;

        XmmGrid.Columns.Clear();
        XmmGrid.Columns.Add(new DataGridTextColumn
        {
            Header = "Reg",
            Width = 60,
            Binding = new Binding(nameof(XmmRow.Name))
        });

        if (asDouble)
        {
            XmmGrid.Columns.Add(new DataGridTextColumn
            {
                Header = "Double 0",
                Width = 160,
                Binding = new Binding(nameof(XmmRow.V0))
            });
            XmmGrid.Columns.Add(new DataGridTextColumn
            {
                Header = "Double 1",
                Width = 160,
                Binding = new Binding(nameof(XmmRow.V1))
            });
        }
        else
        {
            for (int i = 0; i < 4; i++)
            {
                XmmGrid.Columns.Add(new DataGridTextColumn
                {
                    Header = $"Float {i}",
                    Width = 110,
                    Binding = new Binding($"V{i}")
                });
            }
        }

        XmmGrid.Columns.Add(new DataGridTextColumn
        {
            Header = "Hex",
            Width = new DataGridLength(1, DataGridLengthUnitType.Star),
            Binding = new Binding(nameof(XmmRow.Hex))
        });

        XmmGrid.ItemsSource = _record.Xmm.Select((r, i) => new XmmRow(
            $"XMM{i}",
            asDouble ? HitRecord.FormatDouble(r.Doubles[0]) : HitRecord.FormatDouble(r.Singles[0]),
            asDouble ? HitRecord.FormatDouble(r.Doubles[1]) : HitRecord.FormatDouble(r.Singles[1]),
            asDouble ? string.Empty : HitRecord.FormatDouble(r.Singles[2]),
            asDouble ? string.Empty : HitRecord.FormatDouble(r.Singles[3]),
            r.Hex)).ToList();
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(BuildReport());
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Copy", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private string BuildReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine(HeaderText.Text);
        sb.AppendLine();

        sb.AppendLine("General purpose");
        foreach (RegisterValue g in _record.Gprs)
            sb.AppendLine($"  {g.Name,-6} {g.Display}");
        sb.AppendLine();

        sb.AppendLine("Flags");
        sb.AppendLine($"  EFLAGS 0x{_record.EFlags:X8}   MXCSR 0x{_record.MxCsr:X8}");
        sb.AppendLine();

        sb.AppendLine("Segments");
        foreach (RegisterValue g in _record.Segments)
            sb.AppendLine($"  {g.Name,-4} {g.Display}");
        sb.AppendLine();

        sb.AppendLine("Debug registers");
        foreach (RegisterValue g in _record.DebugRegisters)
            sb.AppendLine($"  {g.Name,-4} {g.Display}");
        sb.AppendLine();

        sb.AppendLine("x87 (ST0-ST7)");
        for (int i = 0; i < _record.X87.Length; i++)
        {
            X87Register r = _record.X87[i];
            sb.AppendLine($"  ST{i}  {(r.Empty ? "(empty)" : $"{r.ValueText}   [0x{r.Hex}]")}");
        }
        sb.AppendLine();

        bool asDouble = AsDouble;
        sb.AppendLine($"SSE (XMM) - {(asDouble ? "double" : "float")}");
        for (int i = 0; i < _record.Xmm.Length; i++)
        {
            XmmRegister r = _record.Xmm[i];
            string values = asDouble
                ? string.Join(", ", r.Doubles.Select(HitRecord.FormatDouble))
                : string.Join(", ", r.Singles.Select(f => HitRecord.FormatDouble(f)));
            sb.AppendLine($"  XMM{i,-3} {values}   [0x{r.Hex}]");
        }

        return sb.ToString();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
