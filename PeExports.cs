using System.Text;

namespace OmniHax;

/// <summary>
/// Resolves an export address by parsing the loaded module's PE export directory
/// straight out of the target process. Works for 32-bit and 64-bit targets and
/// follows export forwarders.
/// </summary>
internal static class PeExports
{
    public static bool TryResolve(ProcessMemory memory, string moduleName, string functionName, out ulong address)
    {
        address = 0;
        if (!TargetModules.TryFindBase(memory.Handle, moduleName, out ulong moduleBase))
            return false;

        return ResolveInModule(memory, moduleBase, moduleName, functionName, out address,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    private static bool ResolveInModule(ProcessMemory memory, ulong moduleBase, string moduleName,
        string functionName, out ulong address, HashSet<string> visited)
    {
        address = 0;
        visited.Add(moduleName);

        byte[] header = memory.ReadBytes(moduleBase, 0x1000) ?? Array.Empty<byte>();
        if (header.Length < 0x40)
            return false;

        int peOffset = BitConverter.ToInt32(header, 0x3C);
        if (peOffset <= 0 || peOffset + 24 > header.Length)
            return false;
        if (BitConverter.ToUInt32(header, peOffset) != 0x00004550)
            return false;

        int optional = peOffset + 24;
        if (optional + 2 > header.Length)
            return false;

        ushort magic = BitConverter.ToUInt16(header, optional);
        int dataDirectory = magic switch
        {
            0x10B => optional + 0x60,
            0x20B => optional + 0x70,
            _ => -1
        };
        if (dataDirectory < 0 || dataDirectory + 8 > header.Length)
            return false;

        uint exportRva = BitConverter.ToUInt32(header, dataDirectory);
        uint exportSize = BitConverter.ToUInt32(header, dataDirectory + 4);
        if (exportRva == 0 || exportSize == 0)
            return false;

        byte[] dir = memory.ReadBytes(moduleBase + exportRva, 40) ?? Array.Empty<byte>();
        if (dir.Length < 40)
            return false;

        uint numberOfFunctions = BitConverter.ToUInt32(dir, 0x14);
        uint numberOfNames = BitConverter.ToUInt32(dir, 0x18);
        uint addressOfFunctions = BitConverter.ToUInt32(dir, 0x1C);
        uint addressOfNames = BitConverter.ToUInt32(dir, 0x20);
        uint addressOfNameOrdinals = BitConverter.ToUInt32(dir, 0x24);
        if (numberOfFunctions == 0 || numberOfNames == 0)
            return false;

        byte[] names = memory.ReadBytes(moduleBase + addressOfNames, (int)numberOfNames * 4) ?? Array.Empty<byte>();
        byte[] ordinals = memory.ReadBytes(moduleBase + addressOfNameOrdinals, (int)numberOfNames * 2) ?? Array.Empty<byte>();
        if (names.Length < (int)numberOfNames * 4 || ordinals.Length < (int)numberOfNames * 2)
            return false;

        for (int i = 0; i < (int)numberOfNames; i++)
        {
            uint nameRva = BitConverter.ToUInt32(names, i * 4);
            string name = ReadAscii(memory, moduleBase + nameRva, 256);
            if (!string.Equals(name, functionName, StringComparison.Ordinal))
                continue;

            ushort ordinal = BitConverter.ToUInt16(ordinals, i * 2);
            if (ordinal >= numberOfFunctions)
                return false;

            byte[] function = memory.ReadBytes(moduleBase + addressOfFunctions + (uint)ordinal * 4, 4) ?? Array.Empty<byte>();
            if (function.Length < 4)
                return false;

            uint functionRva = BitConverter.ToUInt32(function, 0);

            if (functionRva >= exportRva && functionRva < exportRva + exportSize)
            {
                string forwarder = ReadAscii(memory, moduleBase + functionRva, 256);
                int dot = forwarder.IndexOf('.');
                if (dot <= 0)
                    return false;

                string forwardModule = forwarder[..dot];
                string forwardFunction = forwarder[(dot + 1)..];
                if (!forwardModule.Contains('.', StringComparison.Ordinal))
                    forwardModule += ".dll";
                if (visited.Contains(forwardModule))
                    return false;
                if (!TargetModules.TryFindBase(memory.Handle, forwardModule, out ulong forwardBase))
                    return false;

                return ResolveInModule(memory, forwardBase, forwardModule, forwardFunction, out address, visited);
            }

            address = moduleBase + functionRva;
            return true;
        }

        return false;
    }

    private static string ReadAscii(ProcessMemory memory, ulong address, int max)
    {
        byte[] buffer = memory.ReadBytes(address, max) ?? Array.Empty<byte>();
        int length = Array.IndexOf(buffer, (byte)0);
        if (length < 0)
            length = buffer.Length;
        return Encoding.ASCII.GetString(buffer, 0, length);
    }
}
