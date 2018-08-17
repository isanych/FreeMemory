using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FreeMemory
{
    //Declaration of structures
    //SYSTEM_CACHE_INFORMATION
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct SYSTEM_CACHE_INFORMATION
    {
        public uint CurrentSize;
        public uint PeakSize;
        public uint PageFaultCount;
        public uint MinimumWorkingSet;
        public uint MaximumWorkingSet;
        public uint Unused1;
        public uint Unused2;
        public uint Unused3;
        public uint Unused4;
    }

    //SYSTEM_CACHE_INFORMATION_64_BIT
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct SYSTEM_CACHE_INFORMATION_64_BIT
    {
        public long CurrentSize;
        public long PeakSize;
        public long PageFaultCount;
        public long MinimumWorkingSet;
        public long MaximumWorkingSet;
        public long Unused1;
        public long Unused2;
        public long Unused3;
        public long Unused4;
    }

    //TokPriv1Luid
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid
    {
        public int Count;
        public long Luid;
        public int Attr;
    }
    public class Program
    {
        //Declaration of constants
        private const int SE_PRIVILEGE_ENABLED = 2;
        private const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        private const string SE_PROFILE_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
        private const int SystemFileCacheInformation = 0x0015;
        private const int SystemMemoryListInformation = 0x0050;
        private const int MemoryPurgeStandbyList = 4;
        private const int MemoryEmptyWorkingSets = 2;

        //Import of DLL's (API) and the necessary functions 
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("ntdll.dll")]
        public static extern uint NtSetSystemInformation(int InfoClass, IntPtr Info, int Length);

        [DllImport("psapi.dll")]
        private static extern int EmptyWorkingSet(IntPtr hwProc);

        private static void print(string name, List<string> l)
        {
            Console.WriteLine(name + " PROCESSES: " + l.Count);
            Console.WriteLine("-------------------------------");
            foreach (var i in l)
            {
                Console.WriteLine(i);
            }
            Console.WriteLine();
        }

        //Function to clear working set of all processes
        public static void EmptyWorkingSetFunction()
        {
            //Declaration of variables
            var ProcessName = string.Empty;
            var allProcesses = Process.GetProcesses();
            var successProcesses = new List<string>();
            var failProcesses = new List<string>();
            var skipProcesses = new List<string>();
            var skipSet = new HashSet<string>() { "services", "csrss", "wininit", "csrss", "Registry", "Secure System", "smss", "MsMpEng", "System", "Idle" };

            //Cycle through all processes
            for (var i = 0; i < allProcesses.Length; i++)
            {
                var p = new Process();
                p = allProcesses[i];
                //Try to empty the working set of the process, if succesfull add to successProcesses, if failed add to failProcesses with error message
                try
                {
                    ProcessName = p.ProcessName;
                    if (skipSet.Contains(ProcessName))
                    {
                        skipProcesses.Add(ProcessName);
                    }
                    else
                    {
                        EmptyWorkingSet(p.Handle);
                        successProcesses.Add(ProcessName);
                    }
                }
                catch (Exception ex)
                {
                    failProcesses.Add(ProcessName + ": " + ex.Message);
                }
            }

            //Print the lists with successful and failed processes
            print("SUCCESSFULLY CLEARED", successProcesses);
            print("SKIPPED", skipProcesses);
            print("FAILED TO CLEAR", failProcesses);
        }

        //Function to check if OS is 64-bit or not, returns boolean
        public static bool Is64BitMode()
        {
            return Marshal.SizeOf(typeof(IntPtr)) == 8;
        }

        //Function used to clear file system cache, returns boolean
        public static void ClearFileSystemCache(bool ClearStandbyCache)
        {
            try
            {
                //Check if privilege can be increased
                if (SetIncreasePrivilege(SE_INCREASE_QUOTA_NAME))
                {
                    uint num1;
                    int SystemInfoLength;
                    GCHandle gcHandle;
                    //First check which version is running, then fill structure with cache information. Throw error is cache information cannot be read.
                    if (!Is64BitMode())
                    {
                        var cacheInformation = new SYSTEM_CACHE_INFORMATION
                        {
                            MinimumWorkingSet = uint.MaxValue,
                            MaximumWorkingSet = uint.MaxValue
                        };
                        SystemInfoLength = Marshal.SizeOf(cacheInformation);
                        gcHandle = GCHandle.Alloc(cacheInformation, GCHandleType.Pinned);
                        num1 = NtSetSystemInformation(SystemFileCacheInformation, gcHandle.AddrOfPinnedObject(), SystemInfoLength);
                        gcHandle.Free();
                    }
                    else
                    {
                        var information64Bit = new SYSTEM_CACHE_INFORMATION_64_BIT
                        {
                            MinimumWorkingSet = -1L,
                            MaximumWorkingSet = -1L
                        };
                        SystemInfoLength = Marshal.SizeOf(information64Bit);
                        gcHandle = GCHandle.Alloc(information64Bit, GCHandleType.Pinned);
                        num1 = NtSetSystemInformation(SystemFileCacheInformation, gcHandle.AddrOfPinnedObject(), SystemInfoLength);
                        gcHandle.Free();
                    }
                    if (num1 != 0)
                    {
                        throw new Exception("NtSetSystemInformation(SYSTEMCACHEINFORMATION) error: ", new Win32Exception(Marshal.GetLastWin32Error()));
                    }
                }

                //If passes paramater is 'true' and the privilege can be increased, then clear standby lists through MemoryPurgeStandbyList
                if (ClearStandbyCache && SetIncreasePrivilege(SE_PROFILE_SINGLE_PROCESS_NAME))
                {
                    var SystemInfoLength = Marshal.SizeOf(MemoryPurgeStandbyList);
                    var gcHandle = GCHandle.Alloc(MemoryPurgeStandbyList, GCHandleType.Pinned);
                    var num2 = NtSetSystemInformation(SystemMemoryListInformation, gcHandle.AddrOfPinnedObject(), SystemInfoLength);
                    gcHandle.Free();
                    if (num2 != 0)
                    {
                        throw new Exception("NtSetSystemInformation(SYSTEMMEMORYLISTINFORMATION) error: ", new Win32Exception(Marshal.GetLastWin32Error()));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Write(ex.ToString());
            }
        }

        //Function to increase Privilege, returns boolean
        private static bool SetIncreasePrivilege(string privilegeName)
        {
            using (var current = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges))
            {
                TokPriv1Luid newst;
                newst.Count = 1;
                newst.Luid = 0L;
                newst.Attr = SE_PRIVILEGE_ENABLED;

                //Retrieves the LUID used on a specified system to locally represent the specified privilege name
                if (!LookupPrivilegeValue(null, privilegeName, ref newst.Luid))
                {
                    throw new Exception("Error in LookupPrivilegeValue: ", new Win32Exception(Marshal.GetLastWin32Error()));
                }

                //Enables or disables privileges in a specified access token
                var num = AdjustTokenPrivileges(current.Token, false, ref newst, 0, IntPtr.Zero, IntPtr.Zero) ? 1 : 0;
                if (num == 0)
                {
                    throw new Exception("Error in AdjustTokenPrivileges: ", new Win32Exception(Marshal.GetLastWin32Error()));
                }

                return num != 0;
            }
        }

        //MAIN Program
        private static void Main(string[] args)
        {
            //Clear working set of all processes
            EmptyWorkingSetFunction();

            //Clear file system cache
            ClearFileSystemCache(true);

            //Waiting for input of user to close program
            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }
    }
}