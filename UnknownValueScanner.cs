using System.Buffers.Binary;
using System.Numerics;
using System.Runtime;

namespace OmniHax;

internal enum UnknownComparison
{
    Less,
    Greater,
    Equal
}

/// <summary>
/// Unknown-value scans. The first pass copies the scanned regions into
/// per-chunk byte arrays (candidate values are windows at <c>Base + i*Step</c>,
/// so no addresses are stored). Each later pass reads the current bytes with a
/// ping-pong buffer, keeps only the slots whose value changed as requested,
/// refreshes the snapshot, and releases chunks with no live candidates.
/// </summary>
internal sealed class UnknownValueScanner
{
    private const int MaxChunkDataBytes = 4 * 1024 * 1024;

    private readonly ProcessMemory _memory;
    private readonly bool _writableOnly;
    private readonly bool _aligned;
    private readonly int _size;
    private readonly int _threads;
    private readonly List<SnapshotChunk> _chunks = new();

    private long _count;

    public UnknownValueScanner(ProcessMemory memory, MemoryValueType valueType, bool writableOnly, bool aligned, int threads)
    {
        _memory = memory;
        ValueType = valueType;
        _size = MemoryValueTypeInfo.SizeOf(valueType);
        _writableOnly = writableOnly;
        _aligned = aligned;
        _threads = threads;
    }

    public MemoryValueType ValueType { get; }
    public long Count => _count;

    public Task SnapshotAsync(IProgress<ScanProgress>? progress, CancellationToken token) =>
        Task.Run(() => FirstScan(progress, token), token);

    public Task CompareAsync(UnknownComparison comparison, IProgress<ScanProgress>? progress, CancellationToken token) =>
        Task.Run(() => FilterScan(comparison, progress, token), token);

    public IEnumerable<ulong> Addresses(int max)
    {
        int taken = 0;
        foreach (SnapshotChunk chunk in _chunks)
        {
            if (chunk.Alive == 0)
                continue;

            for (int i = chunk.NextActive(0); i >= 0; i = chunk.NextActive(i + 1))
            {
                if (taken >= max)
                    yield break;

                taken++;
                yield return chunk.Base + (ulong)((long)i * chunk.Step);
            }
        }
    }

    private int Degree => _threads > 0 ? _threads : Environment.ProcessorCount;

    private void FirstScan(IProgress<ScanProgress>? progress, CancellationToken token)
    {
        _chunks.Clear();
        _count = 0;

        int step = _aligned ? _size : 1;
        List<MemoryRegion> regions = _memory.EnumerateRegions(_writableOnly);
        var descriptors = new List<SnapshotChunk>();

        foreach (MemoryRegion region in regions)
        {
            ulong position = 0;
            while (position < region.Size)
            {
                long remaining = unchecked((long)(region.Size - position));
                int coverage = (int)Math.Min(MaxChunkDataBytes, remaining);
                int count = _aligned ? coverage / _size : coverage;
                if (count <= 0)
                    break;

                int want = (count - 1) * step + _size;
                descriptors.Add(new SnapshotChunk
                {
                    Base = region.Base + position,
                    Step = step,
                    Size = _size,
                    Count = count,
                    DataLength = (int)Math.Min((long)want, remaining)
                });

                position += (ulong)coverage;
            }
        }

        long bytesScanned = 0;
        long done = 0;
        var options = new ParallelOptions { CancellationToken = token, MaxDegreeOfParallelism = Degree };

        Parallel.For(0, descriptors.Count, options, i =>
        {
            token.ThrowIfCancellationRequested();
            SnapshotChunk chunk = descriptors[i];

            var data = new byte[chunk.DataLength];
            if (!_memory.ReadBytes(chunk.Base, data, chunk.DataLength, out int read) || read < _size)
            {
                chunk.Count = 0;
                chunk.Alive = 0;
                return;
            }

            int usable = _aligned ? Math.Min(chunk.Count, read / _size) : Math.Min(chunk.Count, read - _size + 1);
            if (usable <= 0)
            {
                chunk.Count = 0;
                chunk.Alive = 0;
                return;
            }

            int dataLength = (usable - 1) * step + _size;
            if (dataLength != data.Length)
                Array.Resize(ref data, dataLength);

            chunk.Count = usable;
            chunk.Alive = usable;
            chunk.DataLength = dataLength;
            chunk.Prev = data;
            chunk.Active = new ulong[(usable + 63) / 64];
            SetAll(chunk.Active, usable);

            Interlocked.Add(ref bytesScanned, read);
            long d = Interlocked.Increment(ref done);
            if ((d & 0x3F) == 0 || d == descriptors.Count)
                progress?.Report(new ScanProgress(d, descriptors.Count, Volatile.Read(ref bytesScanned), 0));
        });

        foreach (SnapshotChunk chunk in descriptors)
        {
            if (chunk.Alive > 0)
            {
                _chunks.Add(chunk);
                _count += chunk.Alive;
            }
        }

        progress?.Report(new ScanProgress(_chunks.Count, descriptors.Count, Volatile.Read(ref bytesScanned), _count));
    }

    private void FilterScan(UnknownComparison comparison, IProgress<ScanProgress>? progress, CancellationToken token)
    {
        int chunkCount = _chunks.Count;
        var options = new ParallelOptions { CancellationToken = token, MaxDegreeOfParallelism = Degree };

        Parallel.For(0, chunkCount, options, i =>
        {
            token.ThrowIfCancellationRequested();
            ProcessChunk(_chunks[i], comparison, token);
        });

        ReclaimEmptyChunks();

        _count = 0;
        foreach (SnapshotChunk chunk in _chunks)
            _count += chunk.Alive;

        progress?.Report(new ScanProgress(chunkCount, chunkCount, 0, _count));
    }

    private void ProcessChunk(SnapshotChunk chunk, UnknownComparison comparison, CancellationToken token)
    {
        if (chunk.Alive == 0)
            return;

        int want = chunk.DataLength;
        byte[] curr = chunk.Curr is { } existing && existing.Length == want ? existing : new byte[want];
        chunk.Curr = curr;

        if (!_memory.ReadBytes(chunk.Base, curr, want, out int read) || read < chunk.Size)
        {
            chunk.Alive = 0;
            return;
        }

        int usable = _aligned ? Math.Min(chunk.Count, read / chunk.Size) : Math.Min(chunk.Count, read - chunk.Size + 1);
        int removed = _aligned && chunk.Alive * 4 >= chunk.Count
            ? FilterDense(chunk, curr, usable, comparison)
            : FilterSparse(chunk, curr, read, comparison);

        chunk.Alive -= removed;

        byte[] prev = chunk.Prev;
        chunk.Prev = curr;
        chunk.Curr = prev;
    }

    private int FilterDense(SnapshotChunk chunk, byte[] curr, int usable, UnknownComparison comparison)
    {
        int removed = 0;
        int fullWords = usable >> 6;
        int windowBytes = chunk.Step;
        ulong[] active = chunk.Active;
        byte[] prev = chunk.Prev;

        for (int w = 0; w < fullWords; w++)
        {
            ulong bits = active[w];
            if (bits == 0)
                continue;

            int byteOffset = w * 64 * windowBytes;
            ulong keep = VectorCompare.KeepMask64(ValueType,
                prev.AsSpan(byteOffset, 64 * windowBytes),
                curr.AsSpan(byteOffset, 64 * windowBytes),
                comparison);

            removed += BitOperations.PopCount(bits & ~keep);
            active[w] = bits & keep;
        }

        removed += FilterTail(chunk, curr, fullWords * 64, usable, comparison);
        removed += DiscardRange(chunk, usable, chunk.Count);
        return removed;
    }

    private int FilterSparse(SnapshotChunk chunk, byte[] curr, int read, UnknownComparison comparison)
    {
        int removed = 0;
        byte[] prev = chunk.Prev;

        for (int c = chunk.NextActive(0); c >= 0; c = chunk.NextActive(c + 1))
        {
            int offset = c * chunk.Step;
            if (offset + chunk.Size > read)
            {
                chunk.Clear(c);
                removed++;
                continue;
            }

            ulong previous = ReadRaw(prev, offset);
            ulong current = ReadRaw(curr, offset);
            if (!Matches(comparison, previous, current))
            {
                chunk.Clear(c);
                removed++;
            }
        }

        return removed;
    }

    private int FilterTail(SnapshotChunk chunk, byte[] curr, int from, int to, UnknownComparison comparison)
    {
        int removed = 0;
        byte[] prev = chunk.Prev;

        for (int c = from; c < to; c++)
        {
            if (!chunk.IsActive(c))
                continue;

            int offset = c * chunk.Step;
            ulong previous = ReadRaw(prev, offset);
            ulong current = ReadRaw(curr, offset);
            if (!Matches(comparison, previous, current))
            {
                chunk.Clear(c);
                removed++;
            }
        }

        return removed;
    }

    private static int DiscardRange(SnapshotChunk chunk, int from, int to)
    {
        int removed = 0;
        for (int c = from; c < to; c++)
        {
            if (chunk.IsActive(c))
            {
                chunk.Clear(c);
                removed++;
            }
        }

        return removed;
    }

    private void ReclaimEmptyChunks()
    {
        int original = _chunks.Count;
        int write = 0;
        for (int i = 0; i < original; i++)
        {
            if (_chunks[i].Alive > 0)
                _chunks[write++] = _chunks[i];
        }

        if (write == original)
            return;

        int removed = original - write;
        _chunks.RemoveRange(write, removed);

        // Force a one-time LOH compaction only when a meaningful fraction was released.
        if (removed * 4 >= original)
        {
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Optimized);
        }
    }

    private bool Matches(UnknownComparison comparison, ulong previous, ulong current)
    {
        int cmp = MemoryValueTypeInfo.Compare(ValueType, current, previous);
        return comparison switch
        {
            UnknownComparison.Less => cmp < 0,
            UnknownComparison.Greater => cmp > 0,
            _ => cmp == 0
        };
    }

    private ulong ReadRaw(byte[] data, int offset) => _size switch
    {
        1 => data[offset],
        2 => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset)),
        4 => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset)),
        8 => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset)),
        _ => 0
    };

    private static void SetAll(ulong[] words, int count)
    {
        int full = count >> 6;
        for (int i = 0; i < full; i++)
            words[i] = ulong.MaxValue;

        int remainder = count & 63;
        if (remainder != 0)
            words[full] = (1UL << remainder) - 1;
    }

    private sealed class SnapshotChunk
    {
        public ulong Base;
        public int Step;
        public int Size;
        public int Count;
        public int Alive;
        public int DataLength;
        public byte[] Prev = Array.Empty<byte>();
        public byte[]? Curr;
        public ulong[] Active = Array.Empty<ulong>();

        public bool IsActive(int index) => (Active[index >> 6] & (1UL << (index & 63))) != 0;

        public void Clear(int index) => Active[index >> 6] &= ~(1UL << (index & 63));

        public int NextActive(int from)
        {
            int wordIndex = from >> 6;
            if (wordIndex >= Active.Length)
                return -1;

            ulong word = Active[wordIndex] & (ulong.MaxValue << (from & 63));
            int baseIndex = wordIndex << 6;

            while (true)
            {
                if (word != 0)
                    return baseIndex + BitOperations.TrailingZeroCount(word);

                wordIndex++;
                baseIndex += 64;
                if (wordIndex >= Active.Length)
                    return -1;

                word = Active[wordIndex];
            }
        }
    }
}
