using System.Runtime.InteropServices;
using System.Text;

namespace OmniHax;

internal static class TargetModules
{
    public static List<(string Name, ulong Base, ulong Size)> Enumerate(IntPtr processHandle)
    {
        var result = new List<(string Name, ulong Base, ulong Size)>();
        var modules = new IntPtr[1024];

        bool ok = NativeMethods.EnumProcessModulesEx(
            processHandle, modules, (uint)(modules.Length * IntPtr.Size), out uint needed, NativeMethods.LIST_MODULES_ALL);

        if (!ok)
            ok = NativeMethods.EnumProcessModules(
                processHandle, modules, (uint)(modules.Length * IntPtr.Size), out needed);

        if (!ok)
            return result;

        int count = (int)(needed / IntPtr.Size);
        if (count > modules.Length)
            count = modules.Length;

        var name = new StringBuilder(260);

        for (int i = 0; i < count; i++)
        {
            name.Clear();
            NativeMethods.GetModuleBaseName(processHandle, modules[i], name, (uint)name.Capacity);

            if (!NativeMethods.GetModuleInformation(
                    processHandle, modules[i], out NativeMethods.MODULEINFO info,
                    (uint)Marshal.SizeOf<NativeMethods.MODULEINFO>()))
            {
                continue;
            }

            result.Add((name.ToString(), unchecked((ulong)info.lpBaseOfDll.ToInt64()), info.SizeOfImage));
        }

        return result;
    }

    public static bool TryFindBase(IntPtr processHandle, string moduleName, out ulong baseAddress)
    {
        baseAddress = 0;
        foreach ((string name, ulong moduleBase, ulong _) in Enumerate(processHandle))
        {
            if (string.Equals(name, moduleName, StringComparison.OrdinalIgnoreCase))
            {
                baseAddress = moduleBase;
                return true;
            }
        }

        return false;
    }
}
