// 2009 by NickLowe, version 35.  Via https://processprivileges.codeplex.com/
namespace ProcessPrivileges
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.ComponentModel;
    using System.Runtime.ConstrainedExecution;

    /// <summary>a usable Safe Handle (a handle that clears itself from Kernel when no longer in use)</summary>
    public class SafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        /// <summary>Instanstiate</summary>
        public SafeHandle(IntPtr UnsafeHandle, bool ownsHandle) : base(ownsHandle)
        {
            base.handle = UnsafeHandle;
        }

        /// <summary>Instanstiate</summary>
        public SafeHandle(SafeHandle Base) : base(false)
        {
            var ok = false;
            Base.DangerousAddRef(ref ok);
            base.SetHandle(Base.DangerousGetHandle());
        }

        /// <summary>Instanstiate</summary>
        public SafeHandle() : base(false)
        {
            base.handle = IntPtr.Zero;
        }

        /// <summary>Clear the handle</summary>
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail), System.Security.Permissions.SecurityPermission(System.Security.Permissions.SecurityAction.LinkDemand, UnmanagedCode = true)]
        protected override bool ReleaseHandle()
        {
            if (!NativeMethods.CloseHandle(base.handle))
            {
                throw new Win32Exception();
            }

            base.SetHandle(IntPtr.Zero);
            return true;
        }
    } //  public class SafeHandle : SafeHandleZeroOrMinusOneIsInvalid

    /// <summary>Identifies a safe-handle as being for access privilege use</summary>
    public class AccessTokenHandle : ProcessPrivileges.SafeHandle
    {
        /// <summary>Creates a safe-handle as being for access privilege use</summary>
        /// <param name="process">The Process being given privileges</param>
        /// <param name="tokenAccessRights">Rights to be given/taken</param>
        public AccessTokenHandle(System.Diagnostics.Process process, TokenAccessRights tokenAccessRights)
            : base(NativeMethods.OpenProcessToken(process, tokenAccessRights)) { }
    } // public class AccessTokenHandle : SafeHandle
} // namespace ProcessPrivileges
