using System;
using System.Runtime.InteropServices;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Scans a process's virtual address space for the memory signature of code injection / process
    /// hollowing: committed, PRIVATE (not file-backed) regions that are executable — especially RWX
    /// (PAGE_EXECUTE_READWRITE). Legitimate code lives in image-backed (MEM_IMAGE) regions, so a chunk
    /// of executable *private* memory is where injected shellcode / a hollowed payload runs from.
    ///
    /// Note: JIT engines (.NET, browsers, Java) can also allocate executable private memory, so this is
    /// used as a CONTRIBUTING signal (it raises the score), never a standalone verdict.
    /// </summary>
    public static class MemoryScanner
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint __alignment2;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr address,
            out MEMORY_BASIC_INFORMATION buffer, IntPtr length);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

        public class MemoryScanResult
        {
            public int PrivateExecRegions { get; set; }
            public int RwxRegions { get; set; }
            public long PrivateExecBytes { get; set; }
        }

        public static MemoryScanResult Scan(int pid)
        {
            var result = new MemoryScanResult();
            IntPtr handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (handle == IntPtr.Zero) return result;

            try
            {
                var mbiSize = (IntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                ulong address = 0;
                const ulong maxAddress = 0x00007FFFFFFF0000UL; // user-mode ceiling on x64
                var guard = 0;

                while (address < maxAddress && guard++ < 200000)
                {
                    if (VirtualQueryEx(handle, (IntPtr)address, out var mbi, mbiSize) == IntPtr.Zero)
                        break;

                    if (mbi.RegionSize == 0) break;

                    var isExec = mbi.Protect is PAGE_EXECUTE or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;
                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && isExec)
                    {
                        result.PrivateExecRegions++;
                        result.PrivateExecBytes += (long)mbi.RegionSize;
                        if (mbi.Protect == PAGE_EXECUTE_READWRITE)
                            result.RwxRegions++;
                    }

                    var next = mbi.BaseAddress + mbi.RegionSize;
                    if (next <= address) break; // safety against non-advancing query
                    address = next;
                }
            }
            catch { }
            finally
            {
                CloseHandle(handle);
            }

            return result;
        }
    }
}
