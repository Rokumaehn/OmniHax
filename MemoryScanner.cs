using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime;

namespace OmniHax;

internal sealed record ScanProgress(long RegionsDone, long RegionsTotal, long BytesScanned, long Found);

/// <summary>
/// Performs exact-value scans against a process. The first scan walks all
/// committed regions and records matches in per-chunk bitmaps (candidate
/// addresses are derived from the index, so no address list is kept);
/// subsequent scans re-check only the surviving candidates.
/// </summary>
internal sealed class MemoryScanner
{
    private const int MaxChunkDataBytes = 4 * 1024 * 1024;

    private readonly ProcessMemory _memory;
    private readonly bool _writableOnly;
    private readonly bool _aligned;
    private readonly int _size;
    private readonly int _threads;
    private readonly List<MatchChunk> _chunks = new();

    private byte[] _pattern = Array.Empty<byte>();
    private ulong _patternValue;
    private long _count;

    public MemoryScanner(ProcessMemory memory, MemoryValueType valueType, bool writableOnly, bool aligned, int threads)
    {
        _memory = memory;
        ValueType = valueType;
        _size = MemoryValueTypeInfo.SizeOf(valueType);
        _writableOnly = writableOnly;
        _aligned = aligned;
        _threads = threads;
    }

    public MemoryValueType ValueType { get; }
    public bool HasScanned { get; private set; }
    public long Count => _count;

    public void Reset()
    {
        _chunks.Clear();
        _count = 0;
        HasScanned = false;
    }

    public Task ScanAsync(string searchText, IProgress<ScanProgress>? progress, CancellationToken token)
    {
        if (!MemoryValueTypeInfo.TryParse(ValueType, searchText, out byte[] pattern, out _, out string error))
            throw new FormatException(error);

        _pattern = pattern;
        _patternValue = ReadPattern(pattern);

        return Task.Run(() =>
        {
            if (HasScanned)
                FilterScan(progress, token);
            else
                FirstScan(progress, token);

            HasScanned = true;
        }, token);
    }

    public IEnumerable<ulong> Addresses(int max)
    {
        int taken = 0;
        foreach (MatchChunk chunk in _chunks)
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

    private ulong ReadPattern(byte[] pattern) => _size switch
    {
        1 => pattern[0],
        2 => BinaryPrimitives.ReadUInt16LittleEndian(pattern),
        4 => BinaryPrimitives.ReadUInt32LittleEndian(pattern),
        8 => BinaryPrimitives.ReadUInt64LittleEndian(pattern),
        _ => 0
    };

    private void FirstScan(IProgress<ScanProgress>? progress, CancellationToken token)
    {
        _chunks.Clear();
        _count = 0;

        int step = _aligned ? _size : 1;
        List<MemoryRegion> regions = _memory.EnumerateRegions(_writableOnly);
        var descriptors = new List<MatchChunk>();

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
                descriptors.Add(new MatchChunk
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
        long found = 0;
        var options = new ParallelOptions { CancellationToken = token, MaxDegreeOfParallelism = Degree };

        Parallel.For(0, descriptors.Count, options, i =>
        {
            token.ThrowIfCancellationRequested();
            MatchChunk chunk = descriptors[i];

            byte[] buffer = ArrayPool<byte>.Shared.Rent(chunk.DataLength);
            try
            {
                if (!_memory.ReadBytes(chunk.Base, buffer, chunk.DataLength, out int read) || read < _size)
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

                chunk.Count = usable;
                chunk.Active = new ulong[(usable + 63) / 64];
                int foundInChunk = _aligned
                    ? MatchAligned(chunk, buffer, usable)
                    : MatchUnaligned(chunk, buffer, usable, read);
                chunk.Alive = foundInChunk;

                Interlocked.Add(ref found, foundInChunk);
                Interlocked.Add(ref bytesScanned, read);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            long d = Interlocked.Increment(ref done);
            if ((d & 0x3F) == 0 || d == descriptors.Count)
                progress?.Report(new ScanProgress(d, descriptors.Count, Volatile.Read(ref bytesScanned), Volatile.Read(ref found)));
        });

        foreach (MatchChunk chunk in descriptors)
        {
            if (chunk.Alive > 0)
            {
                _chunks.Add(chunk);
                _count += chunk.Alive;
            }
        }

        progress?.Report(new ScanProgress(_chunks.Count, descriptors.Count, Volatile.Read(ref bytesScanned), _count));
    }

    private int MatchAligned(MatchChunk chunk, byte[] buffer, int usable)
    {
        int fullWords = usable >> 6;
        ulong[] active = chunk.Active;
        int total = 0;

        for (int w = 0; w < fullWords; w++)
        {
            int byteOffset = w * 64 * chunk.Step;
            ulong mask = VectorCompare.EqualsMask64(chunk.Size, buffer.AsSpan(byteOffset, 64 * chunk.Size), _patternValue);
            active[w] = mask;
            total += BitOperations.PopCount(mask);
        }

        for (int c = fullWords * 64; c < usable; c++)
        {
            if (MatchesPattern(buffer, c * chunk.Step))
            {
                active[c >> 6] |= 1UL << (c & 63);
                total++;
            }
        }

        return total;
    }

    private int MatchUnaligned(MatchChunk chunk, byte[] buffer, int usable, int read)
    {
        ReadOnlySpan<byte> span = buffer.AsSpan(0, read);
        ReadOnlySpan<byte> pattern = _pattern;
        ulong[] active = chunk.Active;
        int total = 0;
        int search = 0;

        while (search < usable)
        {
            int index = span.Slice(search).IndexOf(pattern);
            if (index < 0)
                break;

            int candidate = search + index;
            if (candidate >= usable)
                break;

            active[candidate >> 6] |= 1UL << (candidate & 63);
            total++;
            search = candidate + 1;
        }

        return total;
    }

    private void FilterScan(IProgress<ScanProgress>? progress, CancellationToken token)
    {
        int chunkCount = _chunks.Count;
        var options = new ParallelOptions { CancellationToken = token, MaxDegreeOfParallelism = Degree };

        Parallel.For(0, chunkCount, options, i =>
        {
            token.ThrowIfCancellationRequested();
            ProcessChunk(_chunks[i]);
        });

        ReclaimEmptyChunks();

        _count = 0;
        foreach (MatchChunk chunk in _chunks)
            _count += chunk.Alive;

        progress?.Report(new ScanProgress(chunkCount, chunkCount, 0, _count));
    }

    private void ProcessChunk(MatchChunk chunk)
    {
        if (chunk.Alive == 0)
            return;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(chunk.DataLength);
        try
        {
            if (!_memory.ReadBytes(chunk.Base, buffer, chunk.DataLength, out int read) || read < chunk.Size)
            {
                chunk.Alive = 0;
                return;
            }

            int usable = _aligned ? Math.Min(chunk.Count, read / chunk.Size) : Math.Min(chunk.Count, read - chunk.Size + 1);
            int removed = _aligned
                ? FilterAligned(chunk, buffer, usable)
                : FilterSparse(chunk, buffer, usable);
            chunk.Alive -= removed;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private int FilterAligned(MatchChunk chunk, byte[] buffer, int usable)
    {
        int removed = 0;
        int fullWords = usable >> 6;
        ulong[] active = chunk.Active;

        for (int w = 0; w < fullWords; w++)
        {
            ulong bits = active[w];
            if (bits == 0)
                continue;

            int byteOffset = w * 64 * chunk.Step;
            ulong matches = VectorCompare.EqualsMask64(chunk.Size, buffer.AsSpan(byteOffset, 64 * chunk.Size), _patternValue);
            removed += BitOperations.PopCount(bits & ~matches);
            active[w] = bits & matches;
        }

        for (int c = fullWords * 64; c < usable; c++)
        {
            if ((active[c >> 6] & (1UL << (c & 63))) == 0)
                continue;

            if (!MatchesPattern(buffer, c * chunk.Step))
            {
                active[c >> 6] &= ~(1UL << (c & 63));
                removed++;
            }
        }

        removed += DiscardRange(chunk, usable, chunk.Count);
        return removed;
    }

    private int FilterSparse(MatchChunk chunk, byte[] buffer, int usable)
    {
        int removed = 0;

        for (int c = chunk.NextActive(0); c >= 0; c = chunk.NextActive(c + 1))
        {
            if (c >= usable || !MatchesPattern(buffer, c * chunk.Step))
            {
                chunk.Clear(c);
                removed++;
            }
        }

        return removed;
    }

    private static int DiscardRange(MatchChunk chunk, int from, int to)
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

    private bool MatchesPattern(byte[] buffer, int offset) => _size switch
    {
        1 => buffer[offset] == (byte)_patternValue,
        2 => BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(offset)) == (ushort)_patternValue,
        4 => BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset)) == (uint)_patternValue,
        8 => BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(offset)) == _patternValue,
        _ => false
    };

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

    private sealed class MatchChunk
    {
        public ulong Base;
        public int Step;
        public int Size;
        public int Count;
        public int Alive;
        public int DataLength;
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
