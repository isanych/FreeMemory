#pragma warning disable 3009,3008,3001,3003
// 2009 by NickLowe, version 35.  Via https://processprivileges.codeplex.com/
namespace ProcessPrivileges
{
    using System;
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;

    /// <summary>API Calls</summary>
    public static class NativeMethods
    {
#pragma warning disable 1591
        private const string AdvApi32 = "advapi32.dll";
        internal const int ErrorInsufficientBuffer = 0x7a;
        private const string Kernel32 = "kernel32.dll";

        [return: MarshalAs(UnmanagedType.Bool)]
        [SuppressUnmanagedCodeSecurity, DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(AccessTokenHandle accessTokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, ref TokenPrivilegeArray NewPriviledges,
            UInt32 Zero, IntPtr Null1, IntPtr Null2);

        [return: MarshalAs(UnmanagedType.Bool)]
        [SuppressUnmanagedCodeSecurity, DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(AccessTokenHandle accessTokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, IntPtr NewPriviledges,
            int bufferLength, ref IntPtr PriorPriviledges, out int returnLength);

        /// <summary>Close a handle allocated to us by the Kernel</summary>
        /// <param name="handle"></param>
        /// <returns></returns>
        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport(Kernel32, ExactSpelling = true, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [return: MarshalAs(UnmanagedType.Bool)]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1401:PInvokesShouldNotBeVisible"), SuppressUnmanagedCodeSecurity,
        DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(AccessTokenHandle accessTokenHandle, TokenInformationClass tokenInformationClass, ref IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

        [return: MarshalAs(UnmanagedType.Bool)]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1401:PInvokesShouldNotBeVisible"), SuppressUnmanagedCodeSecurity,
        DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupPrivilegeName(string systemName, ref Luid luid, [In, Out] StringBuilder name, [In, Out] ref int nameLength);

        [return: MarshalAs(UnmanagedType.Bool)]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1401:PInvokesShouldNotBeVisible"), SuppressUnmanagedCodeSecurity,
        DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string systemName, string name, ref Luid luid);

        [return: MarshalAs(UnmanagedType.Bool)]
        [SuppressUnmanagedCodeSecurity, DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr unsafeHandle, TokenAccessRights desiredAccess, out IntPtr tokenHandle);

        //        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        //    public unsafe static extern void MemCopy(void* dest, void* src, UIntPtr count);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1401:PInvokesShouldNotBeVisible"),
        DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);

        public static ProcessPrivileges.SafeHandle OpenProcessToken(System.Diagnostics.Process Process, TokenAccessRights RequestedRights)
        {
            var iPtr = IntPtr.Zero;

            if (!OpenProcessToken(Process.Handle, RequestedRights, out iPtr))
            {
                throw new Win32Exception();
            }

            return new ProcessPrivileges.SafeHandle(iPtr, true);
        }

        public static void AdjustTokenPrivileges(AccessTokenHandle accessTokenHandle, bool disableAllPrivileges, TokenPrivilegeArray newPrivileges)
        {
            var res = true;
            try
            {
                res = AdjustTokenPrivileges(accessTokenHandle, disableAllPrivileges, ref newPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
            if (!res)
            {
                throw new Win32Exception();
            }
        }

#pragma warning restore 1591
    } // public static class NativeMethods
} // namespace ProcessPrivileges
