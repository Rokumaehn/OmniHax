using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace OmniHax;

/// <summary>
/// Vectorized comparison of candidate value windows. <see cref="KeepMask64(MemoryValueType, ReadOnlySpan{byte}, ReadOnlySpan{byte}, UnknownComparison)"/>
/// returns a 64-bit mask where bit <c>i</c> is set when candidate <c>i</c> satisfies the comparison.
/// </summary>
internal static class VectorCompare
{
    public static ulong KeepMask64(MemoryValueType type, ReadOnlySpan<byte> prev, ReadOnlySpan<byte> curr, UnknownComparison mode) => type switch
    {
        MemoryValueType.Byte => KeepMask64<byte>(prev, MemoryMarshal.Cast<byte, byte>(curr), mode),
        MemoryValueType.SByte => KeepMask64<sbyte>(MemoryMarshal.Cast<byte, sbyte>(prev), MemoryMarshal.Cast<byte, sbyte>(curr), mode),
        MemoryValueType.Word => KeepMask64<ushort>(MemoryMarshal.Cast<byte, ushort>(prev), MemoryMarshal.Cast<byte, ushort>(curr), mode),
        MemoryValueType.Int16 => KeepMask64<short>(MemoryMarshal.Cast<byte, short>(prev), MemoryMarshal.Cast<byte, short>(curr), mode),
        MemoryValueType.DWord => KeepMask64<uint>(MemoryMarshal.Cast<byte, uint>(prev), MemoryMarshal.Cast<byte, uint>(curr), mode),
        MemoryValueType.Int32 => KeepMask64<int>(MemoryMarshal.Cast<byte, int>(prev), MemoryMarshal.Cast<byte, int>(curr), mode),
        MemoryValueType.QWord => KeepMask64<ulong>(MemoryMarshal.Cast<byte, ulong>(prev), MemoryMarshal.Cast<byte, ulong>(curr), mode),
        MemoryValueType.Int64 => KeepMask64<long>(MemoryMarshal.Cast<byte, long>(prev), MemoryMarshal.Cast<byte, long>(curr), mode),
        MemoryValueType.Float => KeepMask64<float>(MemoryMarshal.Cast<byte, float>(prev), MemoryMarshal.Cast<byte, float>(curr), mode),
        MemoryValueType.Double => KeepMask64<double>(MemoryMarshal.Cast<byte, double>(prev), MemoryMarshal.Cast<byte, double>(curr), mode),
        _ => 0UL
    };

    private static ulong KeepMask64<T>(ReadOnlySpan<T> prev, ReadOnlySpan<T> curr, UnknownComparison mode)
        where T : struct
    {
        ulong mask = 0;

        if (Vector256.IsHardwareAccelerated)
        {
            int width = Vector256<T>.Count;
            for (int offset = 0; offset < 64; offset += width)
            {
                var p = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(prev.Slice(offset, width)));
                var c = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(curr.Slice(offset, width)));
                mask |= (ulong)Compare(c, p, mode).ExtractMostSignificantBits() << offset;
            }

            return mask;
        }

        if (Vector128.IsHardwareAccelerated)
        {
            int width = Vector128<T>.Count;
            for (int offset = 0; offset < 64; offset += width)
            {
                var p = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(prev.Slice(offset, width)));
                var c = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(curr.Slice(offset, width)));
                mask |= (ulong)Compare(c, p, mode).ExtractMostSignificantBits() << offset;
            }

            return mask;
        }

        for (int i = 0; i < 64; i++)
        {
            if (CompareScalar(curr[i], prev[i], mode))
                mask |= 1UL << i;
        }

        return mask;
    }

    private static Vector256<T> Compare<T>(Vector256<T> current, Vector256<T> previous, UnknownComparison mode)
        where T : struct => mode switch
        {
            UnknownComparison.Less => Vector256.LessThan(current, previous),
            UnknownComparison.Greater => Vector256.GreaterThan(current, previous),
            _ => Vector256.Equals(current, previous)
        };

    private static Vector128<T> Compare<T>(Vector128<T> current, Vector128<T> previous, UnknownComparison mode)
        where T : struct => mode switch
        {
            UnknownComparison.Less => Vector128.LessThan(current, previous),
            UnknownComparison.Greater => Vector128.GreaterThan(current, previous),
            _ => Vector128.Equals(current, previous)
        };

    private static bool CompareScalar<T>(T current, T previous, UnknownComparison mode)
        where T : struct
    {
        int comparison = Comparer<T>.Default.Compare(current, previous);
        return mode switch
        {
            UnknownComparison.Less => comparison < 0,
            UnknownComparison.Greater => comparison > 0,
            _ => comparison == 0
        };
    }

    /// <summary>
    /// Returns a 64-bit mask where bit <c>i</c> is set when the <c>i</c>-th value of
    /// width <paramref name="size"/> in <paramref name="data"/> equals <paramref name="pattern"/>
    /// bit-for-bit (unsigned lanes, so float/double patterns match exact bytes).
    /// </summary>
    public static ulong EqualsMask64(int size, ReadOnlySpan<byte> data, ulong pattern) => size switch
    {
        1 => EqualsMask64<byte>(data, (byte)pattern),
        2 => EqualsMask64<ushort>(MemoryMarshal.Cast<byte, ushort>(data), (ushort)pattern),
        4 => EqualsMask64<uint>(MemoryMarshal.Cast<byte, uint>(data), (uint)pattern),
        8 => EqualsMask64<ulong>(MemoryMarshal.Cast<byte, ulong>(data), pattern),
        _ => 0UL
    };

    private static ulong EqualsMask64<T>(ReadOnlySpan<T> data, T value)
        where T : struct
    {
        ulong mask = 0;

        if (Vector256.IsHardwareAccelerated)
        {
            int width = Vector256<T>.Count;
            var broadcast = Vector256.Create(value);
            for (int offset = 0; offset < 64; offset += width)
            {
                var v = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(data.Slice(offset, width)));
                mask |= (ulong)Vector256.Equals(v, broadcast).ExtractMostSignificantBits() << offset;
            }

            return mask;
        }

        if (Vector128.IsHardwareAccelerated)
        {
            int width = Vector128<T>.Count;
            var broadcast = Vector128.Create(value);
            for (int offset = 0; offset < 64; offset += width)
            {
                var v = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(data.Slice(offset, width)));
                mask |= (ulong)Vector128.Equals(v, broadcast).ExtractMostSignificantBits() << offset;
            }

            return mask;
        }

        for (int i = 0; i < 64; i++)
        {
            if (EqualityComparer<T>.Default.Equals(data[i], value))
                mask |= 1UL << i;
        }

        return mask;
    }
}
