using System.Runtime.InteropServices;

namespace OmniHax;

[Flags]
internal enum ContextParts
{
    DebugRegisters = 1,
    Control = 2,
    Integer = 4,
    Segments = 8,
    FloatingPoint = 16,
    All = DebugRegisters | Control | Integer | Segments | FloatingPoint
}

/// <summary>
/// Bitness-neutral view of a thread context. For 32-bit (WOW64) targets the
/// 32-bit GPRs are zero-extended into the 64-bit fields and R8-R15 stay zero.
/// </summary>
internal struct TargetContext
{
    public ulong Dr0;
    public ulong Dr1;
    public ulong Dr2;
    public ulong Dr3;
    public ulong Dr6;
    public ulong Dr7;
    public uint EFlags;
    public ulong Rip;
    public ulong Rax;
    public ulong Rcx;
    public ulong Rdx;
    public ulong Rbx;
    public ulong Rsp;
    public ulong Rbp;
    public ulong Rsi;
    public ulong Rdi;
    public ulong R8;
    public ulong R9;
    public ulong R10;
    public ulong R11;
    public ulong R12;
    public ulong R13;
    public ulong R14;
    public ulong R15;

    // Segment selectors.
    public ushort SegCs;
    public ushort SegDs;
    public ushort SegEs;
    public ushort SegFs;
    public ushort SegGs;
    public ushort SegSs;

    // x87 / SSE state.
    public ushort FpuControlWord;
    public ushort FpuStatusWord;
    public ushort FpuTagWord;
    public uint MxCsr;
    public byte[]? FpuRegisters; // 80 bytes: 8 x 10 (x87 ST0-ST7)
    public byte[]? XmmRegisters; // 16*16 bytes (x64) or 8*16 bytes (x86)
}

/// <summary>
/// Reads and writes native thread contexts using the API appropriate for the
/// target's bitness (Get/SetThreadContext vs Wow64Get/Wow64SetThreadContext).
/// </summary>
internal static class TargetThreadContext
{
    public static bool TryRead(IntPtr hThread, bool is32Bit, ContextParts parts, out TargetContext context)
    {
        context = default;
        return is32Bit ? TryRead32(hThread, parts, out context) : TryRead64(hThread, parts, out context);
    }

    public static bool TryWrite(IntPtr hThread, bool is32Bit, in TargetContext context, ContextParts parts)
    {
        return is32Bit ? TryWrite32(hThread, in context, parts) : TryWrite64(hThread, in context, parts);
    }

    private static uint Flags64(ContextParts parts)
    {
        uint flags = 0;
        if ((parts & ContextParts.DebugRegisters) != 0) flags |= NativeMethods.CONTEXT_DEBUG_REGISTERS;
        if ((parts & ContextParts.Control) != 0) flags |= NativeMethods.CONTEXT_CONTROL;
        if ((parts & ContextParts.Integer) != 0) flags |= NativeMethods.CONTEXT_INTEGER;
        if ((parts & ContextParts.Segments) != 0) flags |= NativeMethods.CONTEXT_SEGMENTS;
        if ((parts & ContextParts.FloatingPoint) != 0) flags |= NativeMethods.CONTEXT_FLOATING_POINT;
        return flags;
    }

    private static uint Flags32(ContextParts parts)
    {
        uint flags = 0;
        if ((parts & ContextParts.DebugRegisters) != 0) flags |= NativeMethods.WOW64_CONTEXT_DEBUG_REGISTERS;
        if ((parts & ContextParts.Control) != 0) flags |= NativeMethods.WOW64_CONTEXT_CONTROL;
        if ((parts & ContextParts.Integer) != 0) flags |= NativeMethods.WOW64_CONTEXT_INTEGER;
        if ((parts & ContextParts.Segments) != 0) flags |= NativeMethods.WOW64_CONTEXT_SEGMENTS;
        if ((parts & ContextParts.FloatingPoint) != 0)
            flags |= NativeMethods.WOW64_CONTEXT_FLOATING_POINT | NativeMethods.WOW64_CONTEXT_EXTENDED_REGISTERS;
        return flags;
    }

    private static bool TryRead64(IntPtr hThread, ContextParts parts, out TargetContext context)
    {
        context = default;
        IntPtr raw = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.CONTEXT64>() + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);

        try
        {
            var buffer = new NativeMethods.CONTEXT64 { ContextFlags = Flags64(parts) };
            Marshal.StructureToPtr(buffer, aligned, false);
            if (!NativeMethods.GetThreadContext(hThread, aligned))
                return false;

            buffer = Marshal.PtrToStructure<NativeMethods.CONTEXT64>(aligned);
            context.Dr0 = buffer.Dr0;
            context.Dr1 = buffer.Dr1;
            context.Dr2 = buffer.Dr2;
            context.Dr3 = buffer.Dr3;
            context.Dr6 = buffer.Dr6;
            context.Dr7 = buffer.Dr7;
            context.EFlags = buffer.EFlags;
            context.Rip = buffer.Rip;
            context.Rax = buffer.Rax;
            context.Rcx = buffer.Rcx;
            context.Rdx = buffer.Rdx;
            context.Rbx = buffer.Rbx;
            context.Rsp = buffer.Rsp;
            context.Rbp = buffer.Rbp;
            context.Rsi = buffer.Rsi;
            context.Rdi = buffer.Rdi;
            context.R8 = buffer.R8;
            context.R9 = buffer.R9;
            context.R10 = buffer.R10;
            context.R11 = buffer.R11;
            context.R12 = buffer.R12;
            context.R13 = buffer.R13;
            context.R14 = buffer.R14;
            context.R15 = buffer.R15;

            if ((parts & ContextParts.Segments) != 0)
            {
                context.SegCs = (ushort)Marshal.ReadInt16(aligned, 0x38);
                context.SegDs = (ushort)Marshal.ReadInt16(aligned, 0x3A);
                context.SegEs = (ushort)Marshal.ReadInt16(aligned, 0x3C);
                context.SegFs = (ushort)Marshal.ReadInt16(aligned, 0x3E);
                context.SegGs = (ushort)Marshal.ReadInt16(aligned, 0x40);
                context.SegSs = (ushort)Marshal.ReadInt16(aligned, 0x42);
            }

            if ((parts & ContextParts.FloatingPoint) != 0)
            {
                context.FpuControlWord = (ushort)Marshal.ReadInt16(aligned, 0x100);
                context.FpuStatusWord = (ushort)Marshal.ReadInt16(aligned, 0x102);
                context.FpuTagWord = (ushort)Marshal.ReadByte(aligned, 0x104);
                context.MxCsr = (uint)Marshal.ReadInt32(aligned, 0x118);

                var fpu = new byte[80];
                for (int i = 0; i < 8; i++)
                    Marshal.Copy(IntPtr.Add(aligned, 0x120 + i * 16), fpu, i * 10, 10);
                context.FpuRegisters = fpu;

                var xmm = new byte[256];
                Marshal.Copy(IntPtr.Add(aligned, 0x1A0), xmm, 0, 256);
                context.XmmRegisters = xmm;
            }

            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }
    }

    private static bool TryWrite64(IntPtr hThread, in TargetContext context, ContextParts parts)
    {
        IntPtr raw = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.CONTEXT64>() + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);

        try
        {
            var buffer = new NativeMethods.CONTEXT64
            {
                ContextFlags = Flags64(parts),
                Dr0 = context.Dr0,
                Dr1 = context.Dr1,
                Dr2 = context.Dr2,
                Dr3 = context.Dr3,
                Dr6 = context.Dr6,
                Dr7 = context.Dr7,
                EFlags = context.EFlags,
                Rip = context.Rip,
                Rax = context.Rax,
                Rcx = context.Rcx,
                Rdx = context.Rdx,
                Rbx = context.Rbx,
                Rsp = context.Rsp,
                Rbp = context.Rbp,
                Rsi = context.Rsi,
                Rdi = context.Rdi,
                R8 = context.R8,
                R9 = context.R9,
                R10 = context.R10,
                R11 = context.R11,
                R12 = context.R12,
                R13 = context.R13,
                R14 = context.R14,
                R15 = context.R15
            };

            Marshal.StructureToPtr(buffer, aligned, false);
            return NativeMethods.SetThreadContext(hThread, aligned);
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }
    }

    private static bool TryRead32(IntPtr hThread, ContextParts parts, out TargetContext context)
    {
        context = default;
        IntPtr raw = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WOW64_CONTEXT>() + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);

        try
        {
            var buffer = new NativeMethods.WOW64_CONTEXT { ContextFlags = Flags32(parts) };
            Marshal.StructureToPtr(buffer, aligned, false);
            if (!NativeMethods.Wow64GetThreadContext(hThread, aligned))
                return false;

            buffer = Marshal.PtrToStructure<NativeMethods.WOW64_CONTEXT>(aligned);
            context.Dr0 = buffer.Dr0;
            context.Dr1 = buffer.Dr1;
            context.Dr2 = buffer.Dr2;
            context.Dr3 = buffer.Dr3;
            context.Dr6 = buffer.Dr6;
            context.Dr7 = buffer.Dr7;
            context.EFlags = buffer.EFlags;
            context.Rip = buffer.Eip;
            context.Rax = buffer.Eax;
            context.Rcx = buffer.Ecx;
            context.Rdx = buffer.Edx;
            context.Rbx = buffer.Ebx;
            context.Rsp = buffer.Esp;
            context.Rbp = buffer.Ebp;
            context.Rsi = buffer.Esi;
            context.Rdi = buffer.Edi;

            if ((parts & ContextParts.Segments) != 0)
            {
                context.SegGs = (ushort)Marshal.ReadInt16(aligned, 0x8C);
                context.SegFs = (ushort)Marshal.ReadInt16(aligned, 0x90);
                context.SegEs = (ushort)Marshal.ReadInt16(aligned, 0x94);
                context.SegDs = (ushort)Marshal.ReadInt16(aligned, 0x98);
                context.SegCs = (ushort)Marshal.ReadInt16(aligned, 0xBC);
                context.SegSs = (ushort)Marshal.ReadInt16(aligned, 0xC8);
            }

            if ((parts & ContextParts.FloatingPoint) != 0)
            {
                context.FpuControlWord = (ushort)Marshal.ReadInt16(aligned, 0x1C);
                context.FpuStatusWord = (ushort)Marshal.ReadInt16(aligned, 0x20);
                context.FpuTagWord = (ushort)Marshal.ReadInt16(aligned, 0x24);
                context.MxCsr = (uint)Marshal.ReadInt32(aligned, 0xE4);

                var fpu = new byte[80];
                Marshal.Copy(IntPtr.Add(aligned, 0x38), fpu, 0, 80);
                context.FpuRegisters = fpu;

                var xmm = new byte[128];
                Marshal.Copy(IntPtr.Add(aligned, 0x16C), xmm, 0, 128);
                context.XmmRegisters = xmm;
            }

            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }
    }

    private static bool TryWrite32(IntPtr hThread, in TargetContext context, ContextParts parts)
    {
        IntPtr raw = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WOW64_CONTEXT>() + 16);
        IntPtr aligned = (IntPtr)((raw.ToInt64() + 15) & ~15L);

        try
        {
            var buffer = new NativeMethods.WOW64_CONTEXT
            {
                ContextFlags = Flags32(parts),
                Dr0 = (uint)context.Dr0,
                Dr1 = (uint)context.Dr1,
                Dr2 = (uint)context.Dr2,
                Dr3 = (uint)context.Dr3,
                Dr6 = (uint)context.Dr6,
                Dr7 = (uint)context.Dr7,
                EFlags = context.EFlags,
                Eip = (uint)context.Rip,
                Eax = (uint)context.Rax,
                Ecx = (uint)context.Rcx,
                Edx = (uint)context.Rdx,
                Ebx = (uint)context.Rbx,
                Esp = (uint)context.Rsp,
                Ebp = (uint)context.Rbp,
                Esi = (uint)context.Rsi,
                Edi = (uint)context.Rdi
            };

            Marshal.StructureToPtr(buffer, aligned, false);
            return NativeMethods.Wow64SetThreadContext(hThread, aligned);
        }
        finally
        {
            Marshal.FreeHGlobal(raw);
        }
    }
}
