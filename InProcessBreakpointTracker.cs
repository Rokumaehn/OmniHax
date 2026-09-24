using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace OmniHax;

/// <summary>
/// Tracks writes to an address using a hardware breakpoint (DR0) whose exception is
/// handled by a Vectored Exception Handler injected into the target. No debugger is
/// attached, so ThreadHideFromDebugger (which only suppresses debug events) does not
/// prevent the handler from recording hits.
/// </summary>
internal sealed class InProcessBreakpointTracker : IAccessTracker, IDisposable
{
    private readonly ProcessMemory _memory;
    private readonly DisassemblyService _disassembly;
    private readonly ulong _watchAddress;
    private readonly int _size;
    private readonly AccessKind _mode;
    private readonly bool _is32Bit;
    private readonly AgentLayout _layout;
    private readonly MemoryValueType? _valueType;
    private SynchronizationContext? _ui;
    private readonly ConcurrentQueue<string> _log = new();
    private readonly ConcurrentDictionary<ulong, AccessHit> _hits = new();
    private readonly ConcurrentDictionary<uint, DebugRegisters> _armed = new();
    private readonly List<(ulong Base, ulong End, string Name)> _modules = new();

    private ulong _codeBase;
    private ulong _entriesBase;
    private volatile bool _running;
    private bool _disposed;
    private CancellationTokenSource? _cts;
    private Thread? _pollThread;
    private Thread? _armThread;
    private long _readCursor;
    private int _hitLogCount;

    public InProcessBreakpointTracker(ProcessMemory memory, DisassemblyService disassembly, ulong address, int size,
        AccessKind mode = AccessKind.Write, MemoryValueType? valueType = null)
    {
        _memory = memory;
        _disassembly = disassembly;
        _mode = mode;
        _is32Bit = !memory.Is64BitProcess;
        _layout = _is32Bit ? AgentLayout.X86 : AgentLayout.X64;
        _valueType = valueType;

        if (mode == AccessKind.Execute)
        {
            _size = 1;
            _watchAddress = address;
        }
        else
        {
            _size = Math.Clamp(size <= 0 ? 4 : size, 1, 8);
            _watchAddress = address & ~((ulong)_size - 1);
        }

        IsAligned = _watchAddress == address;
    }

    public bool IsRunning => _running;
    public ulong WatchedAddress => _watchAddress;
    public int WatchedSize => _size;
    public bool IsAligned { get; }
    public event Action? HitsChanged;

    public IReadOnlyCollection<AccessHit> GetHits() =>
        _hits.Values.OrderBy(h => h.InstructionAddress).ToList();

    public void ClearHits()
    {
        _hits.Clear();

        // Skip any records already queued so they don't repopulate the list.
        var index = new byte[8];
        if (_codeBase != 0 && _memory.ReadBytes(_codeBase + (ulong)_layout.WriteIndexOffset, index, _layout.PointerSize, out _))
            Interlocked.Exchange(ref _readCursor, (long)ReadCounter(index));
    }

    public IReadOnlyList<string> DrainLog()
    {
        var lines = new List<string>();
        while (_log.TryDequeue(out string? line))
            lines.Add(line);
        return lines;
    }

    private void Log(string message)
    {
        _log.Enqueue($"{DateTime.Now:HH:mm:ss.fff} {message}");
        while (_log.Count > 4000)
            _log.TryDequeue(out _);
        HardwareBreakpointTracker.Trace?.Invoke(message);
    }

    public void Start()
    {
        if (_running)
            return;

        TargetGuard.Verify(_memory);
        _ui = SynchronizationContext.Current;
        Log($"in-process VEH: start: target verified (pid={_memory.ProcessId} {_memory.ProcessName})");

        LoadModules();

        Log($"in-process VEH: resolving exports ({( _is32Bit ? "x86" : "x64")})");
        ulong addVeh = ResolveExport("kernel32.dll", "AddVectoredExceptionHandler");
        ulong getTid = ResolveExport("kernel32.dll", "GetCurrentThreadId");
        ulong removeVeh = ResolveExport("kernel32.dll", "RemoveVectoredExceptionHandler");
        Log($"in-process VEH: AddVectoredExceptionHandler=0x{addVeh:X} GetCurrentThreadId=0x{getTid:X} RemoveVectoredExceptionHandler=0x{removeVeh:X}");

        IntPtr code = NativeMethods.VirtualAllocEx(
            _memory.Handle, IntPtr.Zero, (IntPtr)_layout.CodeSize,
            NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_EXECUTE_READWRITE);
        if (code == IntPtr.Zero)
            throw new InvalidOperationException($"VirtualAllocEx(code) failed (err={Marshal.GetLastWin32Error()}).");
        _codeBase = unchecked((ulong)code.ToInt64());

        IntPtr entries = NativeMethods.VirtualAllocEx(
            _memory.Handle, IntPtr.Zero, (IntPtr)(_layout.Capacity * _layout.EntrySize),
            NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
        if (entries == IntPtr.Zero)
        {
            NativeMethods.VirtualFreeEx(_memory.Handle, code, IntPtr.Zero, NativeMethods.MEM_RELEASE);
            throw new InvalidOperationException($"VirtualAllocEx(entries) failed (err={Marshal.GetLastWin32Error()}).");
        }
        _entriesBase = unchecked((ulong)entries.ToInt64());
        Log($"in-process VEH: code=0x{_codeBase:X} entries=0x{_entriesBase:X}");

        byte[] blob = ShellcodeAgent.Build(_layout, _codeBase, addVeh, getTid, removeVeh, _entriesBase);
        if (!_memory.WriteBytes(_codeBase, blob))
        {
            NativeMethods.VirtualFreeEx(_memory.Handle, code, IntPtr.Zero, NativeMethods.MEM_RELEASE);
            NativeMethods.VirtualFreeEx(_memory.Handle, entries, IntPtr.Zero, NativeMethods.MEM_RELEASE);
            throw new InvalidOperationException("Failed to write shellcode into the target.");
        }
        Log($"in-process VEH: wrote {blob.Length} bytes of shellcode");

        IntPtr thread = NativeMethods.CreateRemoteThread(
            _memory.Handle, IntPtr.Zero, IntPtr.Zero,
            unchecked((IntPtr)(long)(_codeBase + (ulong)_layout.StubOffset)), IntPtr.Zero, 0, out _);

        if (thread == IntPtr.Zero)
            throw new InvalidOperationException($"CreateRemoteThread failed (err={Marshal.GetLastWin32Error()}).");

        NativeMethods.WaitForSingleObject(thread, 5000);
        NativeMethods.CloseHandle(thread);

        if (NativeMethods.GetExitCodeProcess(_memory.Handle, out uint procExit) && procExit != 259)
            throw new InvalidOperationException($"Target exited during injection (exitCode=0x{procExit:X8}).");

        Log($"in-process VEH: agent at 0x{_codeBase:X}, entries at 0x{_entriesBase:X}, registered");

        ArmAllThreads();

        _running = true;
        _cts = new CancellationTokenSource();
        _pollThread = new Thread(() => PollLoop(_cts.Token)) { IsBackground = true, Name = "OmniHax.VehPoll" };
        _armThread = new Thread(() => ArmLoop(_cts.Token)) { IsBackground = true, Name = "OmniHax.VehArm" };
        _pollThread.Start();
        _armThread.Start();

        Log($"in-process VEH: watching 0x{_watchAddress:X} size={_size} on {_armed.Count} thread(s)");
    }

    private void PollLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                Drain();
            }
            catch (Exception ex)
            {
                Log($"in-process VEH: poll error: {ex.Message}");
            }

            token.WaitHandle.WaitOne(50);
        }
    }

    private void ArmLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            token.WaitHandle.WaitOne(500);
            if (token.IsCancellationRequested)
                break;

            try
            {
                ArmAllThreads();
            }
            catch (Exception ex)
            {
                Log($"in-process VEH: arm error: {ex.Message}");
            }
        }
    }

    private void Drain()
    {
        var index = new byte[8];
        if (!_memory.ReadBytes(_codeBase + (ulong)_layout.WriteIndexOffset, index, _layout.PointerSize, out _))
            return;

        ulong writeIndex = ReadCounter(index);
        long cursor = Interlocked.Read(ref _readCursor);

        if (writeIndex - (ulong)cursor > (ulong)_layout.Capacity)
            cursor = (long)(writeIndex - (ulong)_layout.Capacity);

        var entry = new byte[_layout.EntrySize];

        while ((ulong)cursor < writeIndex)
        {
            ulong slot = (ulong)cursor & (ulong)(_layout.Capacity - 1);
            if (_memory.ReadBytes(_entriesBase + slot * (ulong)_layout.EntrySize, entry, _layout.EntrySize, out _))
            {
                ulong rip = ReadInstructionPointer(entry);
                uint tid = BitConverter.ToUInt32(entry, _layout.PointerSize);
                TargetContext context = BuildContext(entry, rip);
                ProcessHit(rip, tid, in context);
            }

            cursor++;
        }

        Interlocked.Exchange(ref _readCursor, cursor);
    }

    private ulong ReadCounter(byte[] buffer) =>
        _layout.PointerSize == 8 ? BitConverter.ToUInt64(buffer, 0) : BitConverter.ToUInt32(buffer, 0);

    private ulong ReadInstructionPointer(byte[] entry) =>
        _layout.PointerSize == 8 ? BitConverter.ToUInt64(entry, 0) : BitConverter.ToUInt32(entry, 0);

    private sealed record ResolvedAccess(DisassembledInstruction Instruction, AccessKind Kind, ulong EffectiveAddress);

    private void ProcessHit(ulong reportedRip, uint tid, in TargetContext context)
    {
        ResolvedAccess? resolved = ResolveAccess(reportedRip, in context);
        DisassembledInstruction? decoded = resolved?.Instruction;
        ulong instructionAddress = decoded?.Address ?? reportedRip;
        ulong effectiveAddress = resolved?.EffectiveAddress ?? 0;
        AccessKind kind = resolved?.Kind ?? _mode;
        string text = decoded?.Text ?? string.Empty;
        byte[] bytes = decoded?.Bytes ?? Array.Empty<byte>();

        if (!_hits.TryGetValue(instructionAddress, out AccessHit? hit))
        {
            hit = new AccessHit(instructionAddress, tid, kind, text, bytes, effectiveAddress);
            _hits[instructionAddress] = hit;

            if (Interlocked.Increment(ref _hitLogCount) <= 50)
                Log($"hit {kind} at 0x{instructionAddress:X} ({Describe(instructionAddress)}) tid={tid} eff=0x{effectiveAddress:X}: {text}");

            HitsChanged?.Invoke();
        }
        else
        {
            hit.Count++;
            if (!string.IsNullOrEmpty(text))
                hit.Disassembly = text;
        }

        ulong readAt = effectiveAddress != 0 ? effectiveAddress : _watchAddress;
        byte[] valueBytes = _memory.ReadBytes(readAt, _size) ?? Array.Empty<byte>();
        HitRecord record = HitRecord.Create(in context, _is32Bit, tid, kind, effectiveAddress, reportedRip,
            _valueType, valueBytes, DateTime.Now);
        AppendRecord(hit, record);
    }

    private void AppendRecord(AccessHit hit, HitRecord record)
    {
        if (_ui is null)
        {
            hit.Records.Add(record);
            return;
        }

        _ui.Post(_ => hit.Records.Add(record), null);
    }

    /// <summary>
    /// Data breakpoints are reported after the accessing instruction, so prefer the
    /// instruction ending at the reported RIP whose operand resolves onto the watched
    /// address (using the captured registers). Execute breakpoints fault at the
    /// instruction, so decode forward at the RIP.
    /// </summary>
    private ResolvedAccess? ResolveAccess(ulong reportedRip, in TargetContext context)
    {
        if (_mode == AccessKind.Execute)
        {
            DisassembledInstruction? at = DecodeAt(reportedRip);
            return at is null ? null : new ResolvedAccess(at, AccessKind.Execute, reportedRip);
        }

        var candidates = new List<DisassembledInstruction>();
        candidates.AddRange(_disassembly.DecodeEndingAt(_memory, reportedRip).Where(c => !c.Instruction.IsInvalid));

        byte[] raw = _memory.ReadBytes(reportedRip, 15) ?? Array.Empty<byte>();
        List<DisassembledInstruction> forward = _disassembly.Decode(raw, reportedRip, 1);
        if (forward.Count > 0 && !forward[0].Instruction.IsInvalid)
            candidates.Add(forward[0]);

        var factory = new Iced.Intel.InstructionInfoFactory();

        foreach (DisassembledInstruction candidate in candidates)
        {
            ref readonly Iced.Intel.InstructionInfo info = ref factory.GetInfo(candidate.Instruction);

            foreach (Iced.Intel.UsedMemory memory in info.GetUsedMemory())
            {
                if (!MatchesMode(memory.Access))
                    continue;

                if (!RegisterAddress.TryCompute(memory, in context, out ulong address))
                    continue;

                if (RegisterAddress.Overlaps(address, memory, _watchAddress, _size))
                    return new ResolvedAccess(candidate, Classify(memory.Access), address);
            }
        }

        DisassembledInstruction? best = candidates
            .OrderByDescending(c => ScoreAccess(c.Instruction))
            .ThenByDescending(c => c.Length)
            .FirstOrDefault();

        return best is null ? null : new ResolvedAccess(best, ClassifyInstruction(best.Instruction), 0);
    }

    private AccessKind ClassifyInstruction(Iced.Intel.Instruction instruction)
    {
        var factory = new Iced.Intel.InstructionInfoFactory();
        ref readonly Iced.Intel.InstructionInfo info = ref factory.GetInfo(instruction);

        foreach (Iced.Intel.UsedMemory memory in info.GetUsedMemory())
        {
            if (MatchesMode(memory.Access))
                return Classify(memory.Access);
        }

        return _mode;
    }

    private DisassembledInstruction? DecodeAt(ulong address)
    {
        byte[] raw = _memory.ReadBytes(address, 15) ?? Array.Empty<byte>();
        List<DisassembledInstruction> list = _disassembly.Decode(raw, address, 1);
        return list.Count > 0 && !list[0].Instruction.IsInvalid ? list[0] : null;
    }

    private bool MatchesMode(Iced.Intel.OpAccess access) => _mode switch
    {
        AccessKind.Write => RegisterAddress.IsWrite(access),
        AccessKind.Read => RegisterAddress.IsRead(access),
        _ => RegisterAddress.IsRead(access) || RegisterAddress.IsWrite(access)
    };

    private static AccessKind Classify(Iced.Intel.OpAccess access)
    {
        bool read = RegisterAddress.IsRead(access);
        bool write = RegisterAddress.IsWrite(access);

        if (read && write)
            return AccessKind.ReadWrite;
        if (write)
            return AccessKind.Write;
        if (read)
            return AccessKind.Read;
        return AccessKind.Write;
    }

    private TargetContext BuildContext(byte[] entry, ulong rip)
    {
        if (_layout.PointerSize == 8)
        {
            var context = new TargetContext
            {
                Rip = rip,
                EFlags = BitConverter.ToUInt32(entry, ShellcodeAgent.X64SegEflagsOffset + 12),
                SegCs = BitConverter.ToUInt16(entry, ShellcodeAgent.X64SegEflagsOffset + 0),
                SegDs = BitConverter.ToUInt16(entry, ShellcodeAgent.X64SegEflagsOffset + 2),
                SegEs = BitConverter.ToUInt16(entry, ShellcodeAgent.X64SegEflagsOffset + 4),
                SegFs = BitConverter.ToUInt16(entry, ShellcodeAgent.X64SegEflagsOffset + 6),
                SegGs = BitConverter.ToUInt16(entry, ShellcodeAgent.X64SegEflagsOffset + 8),
                SegSs = BitConverter.ToUInt16(entry, ShellcodeAgent.X64SegEflagsOffset + 10),
                Rax = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 0),
                Rcx = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 8),
                Rdx = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 16),
                Rbx = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 24),
                Rsp = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 32),
                Rbp = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 40),
                Rsi = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 48),
                Rdi = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 56),
                R8 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 64),
                R9 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 72),
                R10 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 80),
                R11 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 88),
                R12 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 96),
                R13 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 104),
                R14 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 112),
                R15 = BitConverter.ToUInt64(entry, ShellcodeAgent.X64GprOffset + 120)
            };

            int flt = ShellcodeAgent.X64FltSaveOffset;
            context.FpuControlWord = BitConverter.ToUInt16(entry, flt + 0);
            context.FpuStatusWord = BitConverter.ToUInt16(entry, flt + 2);
            context.FpuTagWord = entry[flt + 4];
            context.MxCsr = BitConverter.ToUInt32(entry, flt + 0x18);

            var fpu = new byte[80];
            for (int i = 0; i < 8; i++)
                Array.Copy(entry, flt + 0x20 + i * 16, fpu, i * 10, 10);
            context.FpuRegisters = fpu;

            var xmm = new byte[256];
            Array.Copy(entry, flt + 0xA0, xmm, 0, 256);
            context.XmmRegisters = xmm;

            return context;
        }
        else
        {
            var context = new TargetContext
            {
                Rip = rip,
                EFlags = BitConverter.ToUInt32(entry, ShellcodeAgent.X86EFlagsOffset),
                SegGs = (ushort)BitConverter.ToUInt32(entry, ShellcodeAgent.X86SegOffset + 0),
                SegFs = (ushort)BitConverter.ToUInt32(entry, ShellcodeAgent.X86SegOffset + 4),
                SegEs = (ushort)BitConverter.ToUInt32(entry, ShellcodeAgent.X86SegOffset + 8),
                SegDs = (ushort)BitConverter.ToUInt32(entry, ShellcodeAgent.X86SegOffset + 12),
                SegCs = (ushort)BitConverter.ToUInt32(entry, ShellcodeAgent.X86SegOffset + 16),
                SegSs = (ushort)BitConverter.ToUInt32(entry, ShellcodeAgent.X86SegOffset + 20),
                Rax = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 0),
                Rcx = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 4),
                Rdx = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 8),
                Rbx = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 12),
                Rsp = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 16),
                Rbp = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 20),
                Rsi = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 24),
                Rdi = BitConverter.ToUInt32(entry, ShellcodeAgent.X86GprOffset + 28),
                FpuControlWord = BitConverter.ToUInt16(entry, ShellcodeAgent.X86FpuCtrlOffset),
                FpuStatusWord = BitConverter.ToUInt16(entry, ShellcodeAgent.X86FpuStatusOffset),
                FpuTagWord = (ushort)BitConverter.ToUInt32(entry, ShellcodeAgent.X86FpuTagOffset)
            };

            var fpu = new byte[80];
            Array.Copy(entry, ShellcodeAgent.X86X87Offset, fpu, 0, 80);
            context.FpuRegisters = fpu;

            var xmm = new byte[128];
            Array.Copy(entry, ShellcodeAgent.X86XmmOffset, xmm, 0, 128);
            context.XmmRegisters = xmm;

            return context;
        }
    }

    private static int ScoreAccess(in Iced.Intel.Instruction instruction)
    {
        if (instruction.IsInvalid)
            return 0;

        var factory = new Iced.Intel.InstructionInfoFactory();
        ref readonly Iced.Intel.InstructionInfo info = ref factory.GetInfo(instruction);

        bool read = false;
        bool write = false;

        foreach (Iced.Intel.UsedMemory memory in info.GetUsedMemory())
        {
            switch (memory.Access)
            {
                case Iced.Intel.OpAccess.Read:
                case Iced.Intel.OpAccess.CondRead:
                    read = true;
                    break;
                case Iced.Intel.OpAccess.Write:
                case Iced.Intel.OpAccess.CondWrite:
                    write = true;
                    break;
                case Iced.Intel.OpAccess.ReadWrite:
                case Iced.Intel.OpAccess.ReadCondWrite:
                    read = true;
                    write = true;
                    break;
            }
        }

        return (read ? 1 : 0) + (write ? 2 : 0);
    }

    private void LoadModules()
    {
        try
        {
            foreach ((string name, ulong b, ulong size) in TargetModules.Enumerate(_memory.Handle))
                _modules.Add((b, b + size, name));

            _modules.Sort((a, b) => a.Base.CompareTo(b.Base));
        }
        catch (Exception ex)
        {
            Log($"module enumeration failed: {ex.Message}");
        }
    }

    private string Describe(ulong address)
    {
        foreach ((ulong start, ulong end, string name) in _modules)
        {
            if (address >= start && address < end)
                return $"{name}+0x{address - start:X}";
        }

        return "?";
    }

    private void ArmAllThreads()
    {
        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
        if (snapshot == IntPtr.Zero || snapshot == (IntPtr)(-1))
        {
            Log($"in-process VEH: thread snapshot failed (err={Marshal.GetLastWin32Error()})");
            return;
        }

        int total = 0;
        int before = _armed.Count;

        try
        {
            var entry = new NativeMethods.THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>() };
            if (!NativeMethods.Thread32First(snapshot, ref entry))
                return;

            do
            {
                if (entry.th32OwnerProcessID != (uint)_memory.ProcessId)
                    continue;

                total++;

                if (!_armed.ContainsKey(entry.th32ThreadID))
                    ArmThread(entry.th32ThreadID);
            }
            while (NativeMethods.Thread32Next(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        Log($"in-process VEH: arm: targetThreads={total} newArmed={_armed.Count - before} totalArmed={_armed.Count}");
    }

    private void ArmThread(uint threadId)
    {
        // No explicit suspension: parking a thread that holds a kernel lock can
        // deadlock the system (CLOCK_WATCHDOG_TIMEOUT). The context APIs do their
        // own kernel-safe synchronization.
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT,
            false,
            threadId);

        if (handle == IntPtr.Zero)
        {
            Log($"in-process VEH: OpenThread({threadId}) failed (err={Marshal.GetLastWin32Error()})");
            return;
        }

        try
        {
            if (!TargetThreadContext.TryRead(handle, _is32Bit, ContextParts.DebugRegisters, out TargetContext context))
            {
                Log($"in-process VEH: GetThreadContext({threadId}) failed (err={Marshal.GetLastWin32Error()})");
                return;
            }

            _armed[threadId] = new DebugRegisters(context.Dr0, context.Dr1, context.Dr2, context.Dr3, context.Dr7);

            int slot = FindFreeSlot(context.Dr7);
            if (slot < 0)
            {
                Log($"in-process VEH: thread {threadId} has no free DR slot");
                return;
            }

            switch (slot)
            {
                case 0: context.Dr0 = _watchAddress; break;
                case 1: context.Dr1 = _watchAddress; break;
                case 2: context.Dr2 = _watchAddress; break;
                default: context.Dr3 = _watchAddress; break;
            }

            context.Dr7 = BuildDr7(context.Dr7, slot);

            if (!TargetThreadContext.TryWrite(handle, _is32Bit, in context, ContextParts.DebugRegisters))
                Log($"in-process VEH: SetThreadContext({threadId}) failed (err={Marshal.GetLastWin32Error()})");
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private static int FindFreeSlot(ulong dr7)
    {
        for (int slot = 0; slot < 4; slot++)
        {
            if ((dr7 & (1UL << (2 * slot))) == 0)
                return slot;
        }

        return -1;
    }

    private ulong BuildDr7(ulong existingDr7, int slot)
    {
        ulong len = _mode == AccessKind.Execute
            ? 0b00UL
            : _size switch
            {
                2 => 0b01UL,
                4 => 0b11UL,
                8 => 0b10UL,
                _ => 0b00UL
            };

        ulong rw = _mode switch
        {
            AccessKind.Execute => 0b00UL, // execute
            AccessKind.Write => 0b01UL,   // write
            _ => 0b11UL                   // read or write
        };

        int rwShift = 16 + 4 * slot;
        int lenShift = 18 + 4 * slot;

        ulong dr7 = existingDr7;
        dr7 |= 1UL << (2 * slot);
        dr7 &= ~(0b11UL << rwShift);
        dr7 |= rw << rwShift;
        dr7 &= ~(0b11UL << lenShift);
        dr7 |= len << lenShift;
        dr7 |= 1UL << 10;              // reserved
        return dr7;
    }

    public void Stop()
    {
        if (!_running && _cts is null)
            return;

        _running = false;
        _cts?.Cancel();

        foreach (Thread? thread in new[] { _pollThread, _armThread })
        {
            if (thread is not null && thread.IsAlive)
            {
                try
                {
                    thread.Join(1000);
                }
                catch (Exception)
                {
                    // ignore
                }
            }
        }

        Log("in-process VEH: cleanup: restoring debug registers");
        try
        {
            RestoreAllThreads();
            Log("in-process VEH: cleared debug registers");
        }
        catch (Exception ex)
        {
            Log($"in-process VEH: restore failed: {ex.Message}");
        }

        try
        {
            TeardownAgent();
        }
        catch (Exception ex)
        {
            Log($"in-process VEH: teardown failed: {ex.Message}");
        }
        finally
        {
            Log("in-process VEH: cleanup done");
        }

        _cts?.Dispose();
        _cts = null;
        _pollThread = null;
        _armThread = null;
    }

    private void TeardownAgent()
    {
        if (_codeBase == 0)
            return;

        ulong codeBase = _codeBase;
        ulong entriesBase = _entriesBase;
        _codeBase = 0;
        _entriesBase = 0;

        try
        {
            if (NativeMethods.GetExitCodeProcess(_memory.Handle, out uint exitCode) && exitCode != 259)
            {
                Log("in-process VEH: target exited; agent memory is gone");
                return;
            }

            var handleBuffer = new byte[8];
            ulong vehHandle = _memory.ReadBytes(codeBase + (ulong)_layout.VehHandleOffset, handleBuffer, _layout.PointerSize, out _)
                ? ReadCounter(handleBuffer)
                : 0;

            bool removed = vehHandle == 0;

            if (vehHandle != 0)
            {
                IntPtr thread = NativeMethods.CreateRemoteThread(
                    _memory.Handle, IntPtr.Zero, IntPtr.Zero,
                    unchecked((IntPtr)(long)(codeBase + (ulong)_layout.TeardownStubOffset)), IntPtr.Zero, 0, out _);

                if (thread != IntPtr.Zero)
                {
                    NativeMethods.WaitForSingleObject(thread, 5000);
                    NativeMethods.CloseHandle(thread);
                    removed = true;
                    Log("in-process VEH: handler removed");
                }
                else
                {
                    Log($"in-process VEH: teardown CreateRemoteThread failed (err={Marshal.GetLastWin32Error()})");
                }
            }
            else
            {
                Log("in-process VEH: no VEH handle recorded; skipping removal");
            }

            if (removed)
            {
                if (entriesBase != 0)
                    NativeMethods.VirtualFreeEx(_memory.Handle, unchecked((IntPtr)(long)entriesBase), IntPtr.Zero, NativeMethods.MEM_RELEASE);
                NativeMethods.VirtualFreeEx(_memory.Handle, unchecked((IntPtr)(long)codeBase), IntPtr.Zero, NativeMethods.MEM_RELEASE);
                Log("in-process VEH: agent memory freed");
            }
            else
            {
                Log("in-process VEH: handler could not be removed; agent left resident");
            }
        }
        catch (Exception ex)
        {
            Log($"in-process VEH: teardown error: {ex.Message}");
        }
    }

    private void RestoreAllThreads()
    {
        foreach (KeyValuePair<uint, DebugRegisters> entry in _armed)
            RestoreThread(entry.Key, entry.Value);
    }

    private void RestoreThread(uint threadId, DebugRegisters original)
    {
        IntPtr handle = NativeMethods.OpenThread(
            NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT,
            false,
            threadId);

        if (handle == IntPtr.Zero)
            return;

        try
        {
            if (TargetThreadContext.TryRead(handle, _is32Bit, ContextParts.DebugRegisters, out TargetContext context))
            {
                context.Dr0 = original.Dr0;
                context.Dr1 = original.Dr1;
                context.Dr2 = original.Dr2;
                context.Dr3 = original.Dr3;
                context.Dr7 = original.Dr7;
                TargetThreadContext.TryWrite(handle, _is32Bit, in context, ContextParts.DebugRegisters);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private ulong ResolveExport(string dllName, string funcName)
    {
        if (!PeExports.TryResolve(_memory, dllName, funcName, out ulong address))
            throw new InvalidOperationException($"Could not resolve {dllName}!{funcName} in the target process.");

        Log($"resolve {dllName}!{funcName} -> 0x{address:X}");
        return address;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Stop();
    }
}
