using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace OmniHax;

internal enum StructureType
{
    Byte,
    SByte,
    Word,
    Int16,
    DWord,
    Int32,
    QWord,
    Int64,
    Float,
    Double,
    Pointer
}

internal sealed record StructureTypeOption(StructureType Type, string DisplayName);

public sealed class StructureRow
{
    public ulong AddressValue { get; init; }
    public string Address { get; init; } = string.Empty;
    public string Hex { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
}

public partial class StructureBrowserWindow : Window
{
    private const int DefaultRows = 128;
    private const int MaxRows = 4096;

    private readonly ProcessMemory _memory;
    private readonly ObservableCollection<StructureRow> _rows = new();
    private ulong _address;

    internal StructureBrowserWindow(ProcessMemory memory, StructureType initialType, ulong address)
    {
        InitializeComponent();

        _memory = memory;
        _address = address;

        StructureGrid.ItemsSource = _rows;

        TypeCombo.ItemsSource = BuildOptions(memory.Is64BitProcess);
        TypeCombo.DisplayMemberPath = nameof(StructureTypeOption.DisplayName);
        TypeCombo.SelectedValuePath = nameof(StructureTypeOption.Type);
        TypeCombo.SelectedValue = initialType;

        RowsBox.Text = DefaultRows.ToString(CultureInfo.InvariantCulture);

        Reload();
    }

    private static StructureTypeOption[] BuildOptions(bool is64Bit)
    {
        var options = new List<StructureTypeOption>();
        foreach (ValueTypeOption option in MemoryValueTypeInfo.Options)
            options.Add(new StructureTypeOption((StructureType)option.Type, option.DisplayName));

        options.Add(new StructureTypeOption(StructureType.Pointer, is64Bit ? "Pointer (64-bit)" : "Pointer (32-bit)"));
        return options.ToArray();
    }

    private StructureType CurrentType =>
        TypeCombo.SelectedValue is StructureType type ? type : StructureType.DWord;

    private int SizeOf(StructureType type) =>
        type == StructureType.Pointer
            ? (_memory.Is64BitProcess ? 8 : 4)
            : MemoryValueTypeInfo.SizeOf((MemoryValueType)type);

    private void GoButton_Click(object sender, RoutedEventArgs e) => GoToTypedAddress();

    private void AddressBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            GoToTypedAddress();
        }
    }

    private void GoToTypedAddress()
    {
        if (CodeEntry.TryParseAddress(AddressBox.Text, out ulong address))
        {
            _address = address;
            Reload();
        }
        else
        {
            StatusText.Text = $"Invalid address '{AddressBox.Text}'.";
        }
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e) => Reload();

    private void RowsBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            Reload();
        }
    }

    private void TypeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded)
            Reload();
    }

    private void Reload()
    {
        _rows.Clear();

        StructureType type = CurrentType;
        int size = SizeOf(type);
        if (size <= 0)
        {
            StatusText.Text = "Select a datatype.";
            return;
        }

        int count = int.TryParse(RowsBox.Text, out int requested) ? Math.Clamp(requested, 1, MaxRows) : DefaultRows;
        AddressBox.Text = $"0x{_address:X}";

        int readable = 0;
        for (int i = 0; i < count; i++)
        {
            ulong rowAddress = _address + (ulong)((long)i * size);
            byte[]? data = _memory.ReadBytes(rowAddress, size);

            if (data is not null)
            {
                readable++;
                _rows.Add(new StructureRow
                {
                    AddressValue = rowAddress,
                    Address = $"0x{rowAddress:X}",
                    Hex = string.Join(' ', data.Select(b => b.ToString("X2"))),
                    Value = Format(type, data, size)
                });
            }
            else
            {
                _rows.Add(new StructureRow
                {
                    AddressValue = rowAddress,
                    Address = $"0x{rowAddress:X}",
                    Hex = "??",
                    Value = "??"
                });
            }
        }

        StatusText.Text = $"{count} row(s) x {size} byte(s) from 0x{_address:X}; {readable} readable.";
    }

    private static string Format(StructureType type, byte[] data, int size)
    {
        if (type == StructureType.Pointer)
        {
            ulong value = size == 8 ? BitConverter.ToUInt64(data) : BitConverter.ToUInt32(data);
            return $"0x{value:X}";
        }

        return MemoryValueTypeInfo.Format((MemoryValueType)type, data);
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
