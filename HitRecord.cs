using System.Globalization;

namespace OmniHax;

internal sealed record RegisterValue(string Name, ulong Value, string Display);

internal sealed class X87Register
{
    public byte[] Raw { get; } = new byte[10];
    public bool Empty { get; set; }
    public double Value { get; set; }
    public string ValueText { get; set; } = string.Empty;
    public string Hex { get; set; } = string.Empty;
}

internal sealed class XmmRegister
{
    public byte[] Raw { get; } = new byte[16];
    public float[] Singles { get; } = new float[4];
    public double[] Doubles { get; } = new double[2];
    public string Hex { get; set; } = string.Empty;
}

/// <summary>One captured access: timestamp, accessed value, and register snapshot.</summary>
internal sealed class HitRecord
{
    public DateTime Timestamp { get; init; }
    public uint ThreadId { get; init; }
    public AccessKind Kind { get; init; }
    public ulong EffectiveAddress { get; init; }
    public ulong InstructionPointer { get; init; }
    public uint EFlags { get; init; }
    public uint MxCsr { get; init; }
    public byte[] ValueBytes { get; init; } = Array.Empty<byte>();
    public string ValueText { get; init; } = string.Empty;
    public IReadOnlyList<RegisterValue> Gprs { get; init; } = Array.Empty<RegisterValue>();
    public RegisterValue[] Segments { get; init; } = Array.Empty<RegisterValue>();
    public RegisterValue[] DebugRegisters { get; init; } = Array.Empty<RegisterValue>();
    public X87Register[] X87 { get; init; } = Array.Empty<X87Register>();
    public XmmRegister[] Xmm { get; init; } = Array.Empty<XmmRegister>();

    public string TimestampText => Timestamp.ToString("HH:mm:ss.fff");
    public string ValueDisplay => ValueText;
    public string Addressing => EffectiveAddress == 0 ? "?" : $"0x{EffectiveAddress:X}";
    public string InstructionPointerText => $"0x{InstructionPointer:X}";
    public string EFlagsText => $"0x{EFlags:X8}";
    public string MxCsrText => $"0x{MxCsr:X8}";

    public static HitRecord Create(in TargetContext context, bool is32Bit, uint threadId, AccessKind kind,
        ulong effectiveAddress, ulong instructionPointer, MemoryValueType? valueType, byte[] valueBytes, DateTime timestamp)
    {
        var gprs = new List<RegisterValue>(16);
        if (is32Bit)
        {
            Add(gprs, "EAX", context.Rax);
            Add(gprs, "ECX", context.Rcx);
            Add(gprs, "EDX", context.Rdx);
            Add(gprs, "EBX", context.Rbx);
            Add(gprs, "ESP", context.Rsp);
            Add(gprs, "EBP", context.Rbp);
            Add(gprs, "ESI", context.Rsi);
            Add(gprs, "EDI", context.Rdi);
        }
        else
        {
            Add(gprs, "RAX", context.Rax);
            Add(gprs, "RCX", context.Rcx);
            Add(gprs, "RDX", context.Rdx);
            Add(gprs, "RBX", context.Rbx);
            Add(gprs, "RSP", context.Rsp);
            Add(gprs, "RBP", context.Rbp);
            Add(gprs, "RSI", context.Rsi);
            Add(gprs, "RDI", context.Rdi);
            Add(gprs, "R8", context.R8);
            Add(gprs, "R9", context.R9);
            Add(gprs, "R10", context.R10);
            Add(gprs, "R11", context.R11);
            Add(gprs, "R12", context.R12);
            Add(gprs, "R13", context.R13);
            Add(gprs, "R14", context.R14);
            Add(gprs, "R15", context.R15);
        }

        var segments = new[]
        {
            Add2("CS", context.SegCs), Add2("DS", context.SegDs), Add2("ES", context.SegEs),
            Add2("FS", context.SegFs), Add2("GS", context.SegGs), Add2("SS", context.SegSs)
        };

        var debug = new[]
        {
            Add2("DR0", context.Dr0), Add2("DR1", context.Dr1), Add2("DR2", context.Dr2),
            Add2("DR3", context.Dr3), Add2("DR6", context.Dr6), Add2("DR7", context.Dr7)
        };

        return new HitRecord
        {
            Timestamp = timestamp,
            ThreadId = threadId,
            Kind = kind,
            EffectiveAddress = effectiveAddress,
            InstructionPointer = instructionPointer,
            EFlags = context.EFlags,
            MxCsr = context.MxCsr,
            ValueBytes = valueBytes,
            ValueText = FormatValue(valueType, valueBytes),
            Gprs = gprs,
            Segments = segments,
            DebugRegisters = debug,
            X87 = ParseX87(context.FpuRegisters, context.FpuTagWord, is32Bit),
            Xmm = ParseXmm(context.XmmRegisters, is32Bit)
        };
    }

    private static void Add(List<RegisterValue> list, string name, ulong value) =>
        list.Add(new RegisterValue(name, value, $"0x{value:X}"));

    private static RegisterValue Add2(string name, ulong value) =>
        new(name, value, $"0x{value:X}");

    public static string FormatValue(MemoryValueType? type, byte[] bytes)
    {
        if (bytes.Length == 0)
            return string.Empty;

        if (type is MemoryValueType t)
        {
            try
            {
                return MemoryValueTypeInfo.Format(t, bytes);
            }
            catch (Exception)
            {
                // fall through to hex
            }
        }

        return bytes.Length switch
        {
            1 => $"0x{bytes[0]:X2}",
            2 => $"0x{BitConverter.ToUInt16(bytes, 0):X4}",
            4 => $"0x{BitConverter.ToUInt32(bytes, 0):X8}",
            8 => $"0x{BitConverter.ToUInt64(bytes, 0):X16}",
            _ => "0x" + Convert.ToHexString(bytes)
        };
    }

    private static X87Register[] ParseX87(byte[]? raw, ushort tagWord, bool is32Bit)
    {
        var result = new X87Register[8];
        for (int i = 0; i < 8; i++)
        {
            var reg = new X87Register();
            if (raw is not null && raw.Length >= (i + 1) * 10)
                Array.Copy(raw, i * 10, reg.Raw, 0, 10);

            reg.Hex = Convert.ToHexString(reg.Raw);
            reg.Empty = raw is null || IsEmpty(tagWord, i, is32Bit);

            if (!reg.Empty)
            {
                reg.Value = X87ToDouble(reg.Raw);
                reg.ValueText = FormatDouble(reg.Value);
            }
            else
            {
                reg.ValueText = "(empty)";
            }

            result[i] = reg;
        }

        return result;
    }

    private static bool IsEmpty(ushort tagWord, int index, bool is32Bit) =>
        is32Bit
            ? ((tagWord >> (2 * index)) & 0x3) == 0x3
            : ((tagWord >> index) & 0x1) != 0;

    private static double X87ToDouble(ReadOnlySpan<byte> b)
    {
        ulong mantissa = 0;
        for (int i = 0; i < 8; i++)
            mantissa |= (ulong)b[i] << (8 * i);

        int se = b[8] | (b[9] << 8);
        bool negative = (se & 0x8000) != 0;
        int exponent = se & 0x7FFF;

        if (exponent == 0 && mantissa == 0)
            return negative ? -0.0 : 0.0;
        if (exponent == 0x7FFF)
            return mantissa == 0 ? (negative ? double.NegativeInfinity : double.PositiveInfinity) : double.NaN;

        double value = mantissa * Math.Pow(2.0, exponent - 16383 - 63);
        return negative ? -value : value;
    }

    private static XmmRegister[] ParseXmm(byte[]? raw, bool is32Bit)
    {
        int count = is32Bit ? 8 : 16;
        var result = new XmmRegister[count];
        for (int i = 0; i < count; i++)
        {
            var reg = new XmmRegister();
            if (raw is not null && raw.Length >= (i + 1) * 16)
            {
                Array.Copy(raw, i * 16, reg.Raw, 0, 16);
                for (int k = 0; k < 4; k++)
                    reg.Singles[k] = BitConverter.ToSingle(reg.Raw, k * 4);
                for (int k = 0; k < 2; k++)
                    reg.Doubles[k] = BitConverter.ToDouble(reg.Raw, k * 8);
            }

            reg.Hex = Convert.ToHexString(reg.Raw);
            result[i] = reg;
        }

        return result;
    }

    public static string FormatDouble(double value)
    {
        if (double.IsNaN(value))
            return "NaN";
        if (double.IsPositiveInfinity(value))
            return "+Inf";
        if (double.IsNegativeInfinity(value))
            return "-Inf";

        if (value == Math.Floor(value) && Math.Abs(value) < 1e15)
            return ((long)value).ToString(CultureInfo.InvariantCulture);

        if ((double)(float)value == value)
            return ((float)value).ToString("R", CultureInfo.InvariantCulture);

        return value.ToString("R", CultureInfo.InvariantCulture);
    }
}
