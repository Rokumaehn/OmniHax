using System.IO;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace OmniHax;

/// <summary>
/// Layout of the injected agent blob for a given target bitness.
/// </summary>
internal sealed record AgentLayout(
    int PointerSize,
    int Capacity,
    int EntrySize,
    int CodeSize,
    int HandlerOffset,
    int StubOffset,
    int TeardownStubOffset,
    int DataOffset,
    int AddVehPtrOffset,
    int GetTidPtrOffset,
    int WriteIndexOffset,
    int EntriesPtrOffset,
    int RemoveVehPtrOffset,
    int VehHandleOffset,
    int RegCount)
{
    public static AgentLayout X64 { get; } = new(
        8, 1 << 14, 0x2A0, 0x1000,
        0x000, 0xA00, 0xA40, 0xA80,
        0xA80, 0xA88, 0xA90, 0xA98, 0xAA0, 0xAA8, 16);

    public static AgentLayout X86 { get; } = new(
        4, 1 << 14, 0x120, 0x1000,
        0x000, 0x600, 0x640, 0x700,
        0x700, 0x704, 0x708, 0x70C, 0x710, 0x714, 8);
}

/// <summary>
/// Builds the VEH agent injected into the target: a registration stub, a
/// teardown stub, and a handler that records STATUS_SINGLE_STEP hits (from DR0)
/// plus the faulting thread's full register state into a ring buffer.
/// Emits x86-64 or x86 depending on the layout.
/// </summary>
internal static class ShellcodeAgent
{
    private const uint StatusSingleStep = 0x80000004;

    // x64 CONTEXT offsets.
    private const int Ctx64Segs = 0x38;   // SegCs..SegSs (12 bytes) + EFlags (4)
    private const int Ctx64Dr6 = 0x68;
    private const int Ctx64Rax = 0x78;
    private const int Ctx64FltSave = 0x100;

    // x86 CONTEXT offsets.
    private const int Ctx32Dr6 = 0x14;
    private const int Ctx32FpuCtrl = 0x1C;
    private const int Ctx32FpuStatus = 0x20;
    private const int Ctx32FpuTag = 0x24;
    private const int Ctx32X87 = 0x38;
    private const int Ctx32Edi = 0x9C;
    private const int Ctx32Esi = 0xA0;
    private const int Ctx32Ebx = 0xA4;
    private const int Ctx32Edx = 0xA8;
    private const int Ctx32Ecx = 0xAC;
    private const int Ctx32Eax = 0xB0;
    private const int Ctx32Ebp = 0xB4;
    private const int Ctx32Cs = 0xBC;
    private const int Ctx32EFlags = 0xC0;
    private const int Ctx32Esp = 0xC4;
    private const int Ctx32Ss = 0xC8;
    private const int Ctx32Gs = 0x8C;
    private const int Ctx32Fs = 0x90;
    private const int Ctx32Es = 0x94;
    private const int Ctx32Ds = 0x98;
    private const int Ctx32Xmm = 0x16C; // ExtendedRegisters + 0xA0

    // Entry offsets (shared with the managed parser).
    public const int X64RipOffset = 0;
    public const int X64TidOffset = 8;
    public const int X64SegEflagsOffset = 16;
    public const int X64GprOffset = 32;
    public const int X64FltSaveOffset = 160;

    public const int X86EipOffset = 0;
    public const int X86TidOffset = 4;
    public const int X86EFlagsOffset = 8;
    public const int X86SegOffset = 12;   // 6 dwords: Gs,Fs,Es,Ds,Cs,Ss
    public const int X86GprOffset = 36;   // 8 dwords: Eax,Ecx,Edx,Ebx,Esp,Ebp,Esi,Edi
    public const int X86FpuCtrlOffset = 68;
    public const int X86FpuStatusOffset = 72;
    public const int X86FpuTagOffset = 76;
    public const int X86X87Offset = 80;   // 80 bytes
    public const int X86XmmOffset = 160;  // 128 bytes

    public static byte[] Build(AgentLayout layout, ulong codeBase,
        ulong addVehPtr, ulong getTidPtr, ulong removeVehPtr, ulong entriesBase)
    {
        byte[] handler = layout.PointerSize == 8 ? AssembleHandler64(layout, codeBase) : AssembleHandler32(layout, codeBase);
        if (handler.Length > layout.StubOffset)
            throw new InvalidOperationException($"Handler shellcode too large ({handler.Length} bytes).");

        byte[] stub = layout.PointerSize == 8 ? AssembleStub64(layout, codeBase) : AssembleStub32(layout, codeBase);
        if (layout.StubOffset + stub.Length > layout.TeardownStubOffset)
            throw new InvalidOperationException($"Stub shellcode too large ({stub.Length} bytes).");

        byte[] teardown = layout.PointerSize == 8
            ? AssembleTeardownStub64(layout, codeBase)
            : AssembleTeardownStub32(layout, codeBase);
        if (layout.TeardownStubOffset + teardown.Length > layout.DataOffset)
            throw new InvalidOperationException($"Teardown shellcode too large ({teardown.Length} bytes).");

        var blob = new byte[layout.CodeSize];
        Array.Copy(handler, 0, blob, layout.HandlerOffset, handler.Length);
        Array.Copy(stub, 0, blob, layout.StubOffset, stub.Length);
        Array.Copy(teardown, 0, blob, layout.TeardownStubOffset, teardown.Length);

        WritePtr(blob, layout.AddVehPtrOffset, addVehPtr, layout.PointerSize);
        WritePtr(blob, layout.GetTidPtrOffset, getTidPtr, layout.PointerSize);
        WritePtr(blob, layout.WriteIndexOffset, 0, layout.PointerSize);
        WritePtr(blob, layout.EntriesPtrOffset, entriesBase, layout.PointerSize);
        WritePtr(blob, layout.RemoveVehPtrOffset, removeVehPtr, layout.PointerSize);
        WritePtr(blob, layout.VehHandleOffset, 0, layout.PointerSize);

        return blob;
    }

    // ---------- x64 ----------

    private static byte[] AssembleHandler64(AgentLayout layout, ulong codeBase)
    {
        var c = new Assembler(64);
        var passSearch = c.CreateLabel();

        // RCX = PEXCEPTION_POINTERS
        c.mov(rdx, __qword_ptr[rcx]);            // ExceptionRecord
        c.mov(eax, __dword_ptr[rdx]);            // ExceptionCode
        c.cmp(eax, StatusSingleStep);
        c.jne(passSearch);

        c.mov(r8, __qword_ptr[rcx + 8]);         // ContextRecord
        c.mov(rax, __qword_ptr[r8 + Ctx64Dr6]);  // Dr6
        c.test(al, 1);
        c.jz(passSearch);

        c.mov(rbx, __qword_ptr[rdx + 0x10]);     // ExceptionAddress (rip)

        c.mov(rax, codeBase + (ulong)layout.GetTidPtrOffset);
        c.mov(rax, __qword_ptr[rax]);
        c.sub(rsp, 0x28);
        c.call(rax);
        c.add(rsp, 0x28);
        c.mov(r9d, eax);

        c.mov(r11, codeBase + (ulong)layout.WriteIndexOffset);
        c.mov(rax, 1);
        c.@lock.xadd(__qword_ptr[r11], rax);
        c.and(rax, layout.Capacity - 1);
        c.imul(rax, rax, layout.EntrySize);

        c.mov(rdx, codeBase + (ulong)layout.EntriesPtrOffset);
        c.mov(rdx, __qword_ptr[rdx]);
        c.add(rdx, rax);

        c.mov(__qword_ptr[rdx + X64RipOffset], rbx);
        c.mov(__dword_ptr[rdx + X64TidOffset], r9d);

        // Segment selectors + EFlags (16 bytes at CONTEXT+0x38).
        c.mov(rax, __qword_ptr[r8 + Ctx64Segs]);
        c.mov(__qword_ptr[rdx + X64SegEflagsOffset], rax);
        c.mov(rax, __qword_ptr[r8 + Ctx64Segs + 8]);
        c.mov(__qword_ptr[rdx + X64SegEflagsOffset + 8], rax);

        // 16 GPRs.
        for (int i = 0; i < 16; i++)
        {
            c.mov(rax, __qword_ptr[r8 + Ctx64Rax + i * 8]);
            c.mov(__qword_ptr[rdx + X64GprOffset + i * 8], rax);
        }

        // 512-byte FP/SSE save area (x87 ST0-7, XMM0-15, MXCSR).
        for (int i = 0; i < 64; i++)
        {
            c.mov(rax, __qword_ptr[r8 + Ctx64FltSave + i * 8]);
            c.mov(__qword_ptr[rdx + X64FltSaveOffset + i * 8], rax);
        }

        c.mov(eax, -1);                          // EXCEPTION_CONTINUE_EXECUTION
        c.ret();

        c.Label(ref passSearch);
        c.xor(eax, eax);                         // EXCEPTION_CONTINUE_SEARCH
        c.ret();

        return Assemble(c, codeBase);
    }

    private static byte[] AssembleStub64(AgentLayout layout, ulong codeBase)
    {
        var c = new Assembler(64);
        c.mov(rcx, 1);                           // First = 1
        c.mov(rdx, codeBase);                    // handler address
        c.mov(rax, codeBase + (ulong)layout.AddVehPtrOffset);
        c.mov(rax, __qword_ptr[rax]);
        c.sub(rsp, 0x28);                        // shadow space + alignment
        c.call(rax);
        c.add(rsp, 0x28);

        c.mov(rcx, codeBase + (ulong)layout.VehHandleOffset);  // store the returned handle
        c.mov(__qword_ptr[rcx], rax);
        c.ret();

        return Assemble(c, codeBase + (ulong)layout.StubOffset);
    }

    private static byte[] AssembleTeardownStub64(AgentLayout layout, ulong codeBase)
    {
        var c = new Assembler(64);
        c.mov(rcx, codeBase + (ulong)layout.VehHandleOffset);
        c.mov(rcx, __qword_ptr[rcx]);
        c.mov(rax, codeBase + (ulong)layout.RemoveVehPtrOffset);
        c.mov(rax, __qword_ptr[rax]);
        c.sub(rsp, 0x28);
        c.call(rax);
        c.add(rsp, 0x28);
        c.ret();

        return Assemble(c, codeBase + (ulong)layout.TeardownStubOffset);
    }

    // ---------- x86 ----------

    private static byte[] AssembleHandler32(AgentLayout layout, ulong codeBase)
    {
        var c = new Assembler(32);
        var passSearch = c.CreateLabel();

        c.push(ebx);
        c.push(esi);
        c.push(edi);
        c.push(ebp);

        c.mov(ecx, __dword_ptr[esp + 20]);       // ExceptionInfo
        c.mov(edx, __dword_ptr[ecx]);            // ExceptionRecord
        c.mov(eax, __dword_ptr[edx]);            // ExceptionCode
        c.cmp(eax, StatusSingleStep);
        c.jne(passSearch);

        c.mov(ebp, __dword_ptr[ecx + 4]);        // ContextRecord (kept across the call)
        c.mov(eax, __dword_ptr[ebp + Ctx32Dr6]);
        c.test(al, 1);
        c.jz(passSearch);

        c.mov(ebx, __dword_ptr[edx + 0x0C]);     // ExceptionAddress (eip)

        c.mov(eax, (uint)(codeBase + (ulong)layout.GetTidPtrOffset));
        c.mov(eax, __dword_ptr[eax]);
        c.call(eax);
        c.mov(esi, eax);                         // tid

        c.mov(eax, 1);
        c.mov(edx, (uint)(codeBase + (ulong)layout.WriteIndexOffset));
        c.@lock.xadd(__dword_ptr[edx], eax);
        c.and(eax, layout.Capacity - 1);
        c.imul(eax, eax, layout.EntrySize);

        c.mov(edx, (uint)(codeBase + (ulong)layout.EntriesPtrOffset));
        c.mov(edx, __dword_ptr[edx]);
        c.add(edx, eax);

        c.mov(__dword_ptr[edx + X86EipOffset], ebx);
        c.mov(__dword_ptr[edx + X86TidOffset], esi);

        c.mov(eax, __dword_ptr[ebp + Ctx32EFlags]);
        c.mov(__dword_ptr[edx + X86EFlagsOffset], eax);

        CopyDword32(c, edx, X86SegOffset + 0, ebp, Ctx32Gs, eax);
        CopyDword32(c, edx, X86SegOffset + 4, ebp, Ctx32Fs, eax);
        CopyDword32(c, edx, X86SegOffset + 8, ebp, Ctx32Es, eax);
        CopyDword32(c, edx, X86SegOffset + 12, ebp, Ctx32Ds, eax);
        CopyDword32(c, edx, X86SegOffset + 16, ebp, Ctx32Cs, eax);
        CopyDword32(c, edx, X86SegOffset + 20, ebp, Ctx32Ss, eax);

        CopyDword32(c, edx, X86GprOffset + 0, ebp, Ctx32Eax, eax);
        CopyDword32(c, edx, X86GprOffset + 4, ebp, Ctx32Ecx, eax);
        CopyDword32(c, edx, X86GprOffset + 8, ebp, Ctx32Edx, eax);
        CopyDword32(c, edx, X86GprOffset + 12, ebp, Ctx32Ebx, eax);
        CopyDword32(c, edx, X86GprOffset + 16, ebp, Ctx32Esp, eax);
        CopyDword32(c, edx, X86GprOffset + 20, ebp, Ctx32Ebp, eax);
        CopyDword32(c, edx, X86GprOffset + 24, ebp, Ctx32Esi, eax);
        CopyDword32(c, edx, X86GprOffset + 28, ebp, Ctx32Edi, eax);

        // FPU control/status/tag and x87 register area.
        CopyDword32(c, edx, X86FpuCtrlOffset, ebp, Ctx32FpuCtrl, eax);
        CopyDword32(c, edx, X86FpuStatusOffset, ebp, Ctx32FpuStatus, eax);
        CopyDword32(c, edx, X86FpuTagOffset, ebp, Ctx32FpuTag, eax);

        for (int i = 0; i < 20; i++)
        {
            c.mov(eax, __dword_ptr[ebp + Ctx32X87 + i * 4]);
            c.mov(__dword_ptr[edx + X86X87Offset + i * 4], eax);
        }

        for (int i = 0; i < 32; i++)
        {
            c.mov(eax, __dword_ptr[ebp + Ctx32Xmm + i * 4]);
            c.mov(__dword_ptr[edx + X86XmmOffset + i * 4], eax);
        }

        c.mov(eax, -1);
        c.pop(ebp);
        c.pop(edi);
        c.pop(esi);
        c.pop(ebx);
        c.ret(4);

        c.Label(ref passSearch);
        c.xor(eax, eax);
        c.pop(ebp);
        c.pop(edi);
        c.pop(esi);
        c.pop(ebx);
        c.ret(4);

        return Assemble(c, codeBase);
    }

    private static void CopyDword32(Assembler c, AssemblerRegister32 dest, int destOffset,
        AssemblerRegister32 source, int sourceOffset, AssemblerRegister32 scratch)
    {
        c.mov(scratch, __dword_ptr[source + sourceOffset]);
        c.mov(__dword_ptr[dest + destOffset], scratch);
    }

    private static byte[] AssembleStub32(AgentLayout layout, ulong codeBase)
    {
        var c = new Assembler(32);

        c.mov(edx, (uint)codeBase);              // handler address
        c.push(edx);                             // Handler (2nd arg pushed first)
        c.push(1);                               // First
        c.mov(eax, (uint)(codeBase + (ulong)layout.AddVehPtrOffset));
        c.mov(eax, __dword_ptr[eax]);
        c.call(eax);

        c.mov(edx, (uint)(codeBase + (ulong)layout.VehHandleOffset));
        c.mov(__dword_ptr[edx], eax);            // store the returned handle
        c.ret(4);                                // thread-start argument cleanup

        return Assemble(c, codeBase + (ulong)layout.StubOffset);
    }

    private static byte[] AssembleTeardownStub32(AgentLayout layout, ulong codeBase)
    {
        var c = new Assembler(32);
        c.mov(ecx, (uint)(codeBase + (ulong)layout.VehHandleOffset));
        c.mov(ecx, __dword_ptr[ecx]);
        c.push(ecx);
        c.mov(eax, (uint)(codeBase + (ulong)layout.RemoveVehPtrOffset));
        c.mov(eax, __dword_ptr[eax]);
        c.call(eax);
        c.ret(4);

        return Assemble(c, codeBase + (ulong)layout.TeardownStubOffset);
    }

    private static byte[] Assemble(Assembler assembler, ulong rip)
    {
        using var stream = new MemoryStream();
        assembler.Assemble(new StreamCodeWriter(stream), rip);
        return stream.ToArray();
    }

    private static void WritePtr(byte[] buffer, int offset, ulong value, int pointerSize)
    {
        for (int i = 0; i < pointerSize; i++)
            buffer[offset + i] = (byte)(value >> (8 * i));
    }
}
