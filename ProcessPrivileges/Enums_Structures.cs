#pragma warning disable 3009,3008,3001,3003
// 2009 by NickLowe, version 35.  Via https://processprivileges.codeplex.com/
namespace ProcessPrivileges
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.InteropServices;

    /// <summary>Some things are static and known, especially once compiled</summary>
    public static class StaticInfo
    {
        /// <summary>We will be working directly with unmanaged memory, so the offsets to our variables need to be known - Count</summary>
        public const uint TokenPrivilegeCount_Offset = 0;
        /// <summary>We will be working directly with unmanaged memory, so the offsets to our variables need to be known - Array of privileges</summary>
        public const uint TokenPrivilegeArray_Offset = sizeof(int);
        /// <summary>Each array element is this size</summary>
        public static uint LuidAndAttributes_Size;

        static unsafe StaticInfo()
        {
            LuidAndAttributes_Size = (uint)sizeof(LuidAndAttributes);
        }
    }

    [Flags]
    internal enum AccessTypeMasks
    {
        Delete = 0x010000,
        ReadControl = 0x020000,
        SpecificRightsAll = 0x00ffff,
        StandardRightsAll = 0x1f0000,
        StandardRightsExecute = 0x020000,
        StandardRightsRead = 0x020000,
        StandardRightsRequired = 0x0f0000,
        StandardRightsWrite = 0x020000,
        Synchronize = 0x100000,
        WriteDAC = 0x040000,
        WriteOwner = 0x080000
    }

    /// <summary>Microsoft's structure for holding unique IDs for privileges</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct Luid
    {
        /// <summary>Low part, UInt32 for matching c++</summary>
        public uint LowPart;
        /// <summary>High part, Int32 for matching c++</summary>
        public int HighPart;
    }

    /// <summary>Kernel defined structure for unique ID &amp; privileges</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct LuidAndAttributes
    {
        /// <summary>Kernel defined - unique identifier</summary>
        [System.Diagnostics.DebuggerDisplay("{Privileges.luidList.Keys[Privileges.luidList.IndexOfValue(Luid)]}")]
        public ProcessPrivileges.Luid // 64 bits
            Luid;
        /// <summary>Kernel defined - Attributes</summary>
        public PrivilegeAttributes // 32 bits
            Attributes;
    }

    /// <summary>Supported Privileges</summary>
    public enum Privilege
    {
#pragma warning disable 1591
        AssignPrimaryToken = 0,
        Audit,
        Backup,
        ChangeNotify,
        CreateGlobal,
        CreatePageFile,
        CreatePermanent,
        CreateSymbolicLink,
        CreateToken,
        Debug,
        EnableDelegation,
        Impersonate,
        IncreaseBasePriority,
        IncreaseQuota,
        IncreaseWorkingSet,
        LoadDriver,
        LockMemory,
        MachineAccount,
        ManageVolume,
        ProfileSingleProcess,
        [SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", Justification = "Spelling is correct.", MessageId = "Relabel")]
        Relabel,
        RemoteShutdown,
        Restore,
        Security,
        Shutdown,
        SyncAgent,
        SystemEnvironment,
        SystemProfile,
        SystemTime,
        TakeOwnership,
        TimeZone,
        TrustedComputerBase,
        TrustedCredentialManagerAccess,
        Undock,
        UnsolicitedInput,
        _MaxInvalid
#pragma warning restore 1591
    }

    /// <summary>Kernel defined - attributes</summary>
    [Flags,
        SuppressMessage("Microsoft.Usage", "CA2217:DoNotMarkEnumsWithFlags", Justification = "Native enum."),
        SuppressMessage("Microsoft.Design", "CA1008:EnumsShouldHaveZeroValue", Justification = "Native enum.")]
    public enum PrivilegeAttributes : uint
    {
#pragma warning disable 1591
        Disabled = 0x00000000,
        Enabled = 0x00000002,
        EnabledByDefault = 0x00000001,
        Removed = 0x00000004,
        UsedForAccess = 0x80000000
#pragma warning restore 1591
    }

    /// <summary>Kernel defined - privilege states</summary>
    public enum PrivilegeState
    {
#pragma warning disable 1591
        Disabled,
        Enabled,
        Removed
#pragma warning restore 1591
    }

    /// <summary>Kernel defined - Access Rights</summary>
    [Flags, SuppressMessage("Microsoft.Design", "CA1008:EnumsShouldHaveZeroValue", Justification = "Native enum."), SuppressMessage("Microsoft.Usage", "CA2217:DoNotMarkEnumsWithFlags", Justification = "Native enum.")]
    public enum TokenAccessRights : uint
    {
#pragma warning disable 1591
        AdjustDefault = 0x00000080,
        AdjustGroups = 0x00000040,
        AdjustPrivileges = 0x00000020,
        AdjustSessionId = 0x00000100,
        AllAccess = 0x000f01fd,
        AssignPrimary = 0x00000000,
        Duplicate = 0x00000001,
        Execute = 0x00020004,
        Impersonate = 0x00000004,
        Query = 0x00000008,
        QuerySource = 0x00000010,
        Read = 0x00020008,
        Write = 0x000200e0
#pragma warning restore 1591
    }

    /// <summary></summary>
    public enum TokenInformationClass
    {
#pragma warning disable 1591
        None,
        TokenUser,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
#pragma warning restore 1591
    }

#pragma warning disable 1591
    [StructLayout(LayoutKind.Sequential)]
    public struct TokenPrivilege
    {
        public int
            PrivilegeCount;
        public LuidAndAttributes
            Privilege;
    }
#pragma warning restore 1591

    /// <summary>Stores unmanaged memory equating to the Kernel Structure TokenPrivilegeArray</summary>
    public class TokenPrivilegeArray : IDisposable
    {
        /// <summary>Internal intptr to unmanaged memory</summary>
        protected IntPtr? _internalPtr;
        /// <summary>copy of the count</summary>
        protected uint _currentCount;

        /// <summary>Current Size of the Array</summary>
        public virtual uint PrivilegeCount
        {
            get
            {
                if (_internalPtr == null)
                {
                    throw new ObjectDisposedException("TokenPrivilegeArray");
                }

                return _currentCount;
            }
            set
            {
                if (_internalPtr == null)
                {
                    throw new ObjectDisposedException("TokenPrivilegeArray");
                }

                Dispose(false);
                _internalPtr = Marshal.AllocHGlobal((int)(StaticInfo.LuidAndAttributes_Size * value + sizeof(uint)));
                Marshal.WriteInt32((IntPtr)_internalPtr, (int)value);
                _currentCount = value;
            }
        }

        /// <summary>Externally accessible IntPtr</summary>
        public virtual IntPtr Ptr
        {
            get
            {
                if (_internalPtr == null)
                {
                    throw new ObjectDisposedException("TokenPrivilegeArray");
                }

                return (IntPtr)_internalPtr;
            }
            set
            {
                if (_internalPtr == null)
                {
                    throw new ObjectDisposedException("TokenPrivilegeArray");
                }

                Dispose(false);
                _internalPtr = value;
                if (value != IntPtr.Zero)
                {
                    _currentCount = (uint)Marshal.ReadInt32(value);
                }
                else
                {
                    _currentCount = 0;
                }
            }
        }

        /// <summary>Copies array into unmanaged memory</summary>
        public virtual LuidAndAttributes[] Privileges
        {
            set
            {
                var src = IntPtr.Zero;
                try
                {
                    PrivilegeCount = (uint)value.Length;
                    var size = StaticInfo.LuidAndAttributes_Size * (uint)value.Length;
                    var dest = new IntPtr(((IntPtr)_internalPtr).ToInt64() + StaticInfo.TokenPrivilegeArray_Offset);
                    src = Marshal.AllocHGlobal((int)size);
                    Marshal.StructureToPtr(value, src, false);
                    NativeMethods.CopyMemory(dest, src, size);
                    //                    NativeMethods.MemCopy(dest.ToPointer(), src.ToPointer(), new UIntPtr(size));
                }
                finally
                {
                    if (src != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(src);
                    }
                }
            }
        }

        /// <summary>Provides a managed copy of the internal array</summary>
        public unsafe LuidAndAttributes[] CopyPrivileges()
        {
            if (_internalPtr == null)
            {
                throw new ObjectDisposedException("TokenPrivilegeArray");
            }

            if (_currentCount < 1)
            {
                return null;
            }

            var result = new LuidAndAttributes[_currentCount];
            var size = _currentCount * StaticInfo.LuidAndAttributes_Size;
            var src = new IntPtr(((IntPtr)_internalPtr).ToInt64() + StaticInfo.TokenPrivilegeArray_Offset);

            fixed (void* p = result)
            {
                NativeMethods.CopyMemory(new IntPtr(p), src, size);
            }

            return result;
        }

        /// <summary>Set the value of a particular position in the array</summary>
        public LuidAndAttributes this[uint Index]
        {
            set
            {
                var src = IntPtr.Zero;
                try
                {
                    if (_internalPtr == null)
                    {
                        throw new ObjectDisposedException("TokenPrivilegeArray");
                    }

                    if (Index >= _currentCount)
                    {
                        throw new IndexOutOfRangeException("Index must be less than length (0 - " + (_currentCount - 1).ToString() + ')');
                    }

                    src = Marshal.AllocHGlobal((int)StaticInfo.LuidAndAttributes_Size);
                    Marshal.StructureToPtr(value, src, false);
                    var dest = new IntPtr(((IntPtr)_internalPtr).ToInt64() + StaticInfo.TokenPrivilegeArray_Offset + Index * StaticInfo.LuidAndAttributes_Size);

                    NativeMethods.CopyMemory(dest, src, StaticInfo.LuidAndAttributes_Size);
                }
                finally
                {
                    if (src != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(src);
                    }
                }
            }
        }

        /// <summary>How much memory is needed to store the array (not counting the Count)</summary>
        public virtual uint CurrentSize => StaticInfo.LuidAndAttributes_Size * _currentCount;

        /// <summary>Instansiate</summary>
        public TokenPrivilegeArray() : this(1) { }

        /// <summary>Instansiate with known array size</summary>
        public TokenPrivilegeArray(uint Count)
        {
            _internalPtr = Marshal.AllocHGlobal((int)(StaticInfo.LuidAndAttributes_Size * Count + sizeof(uint)));
            Marshal.WriteInt32((IntPtr)_internalPtr, (int)Count);
            _currentCount = Count;
        }

        /// <summary>free up memory prior to garbage collection</summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>Dispose - following Microsoft's pattern</summary>
        protected virtual void Dispose(bool IncludeMananged)
        {
            if (_internalPtr != null && _internalPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal((IntPtr)_internalPtr);
                _internalPtr = IntPtr.Zero;
            }
            if (IncludeMananged)
            {
                _internalPtr = null;
                GC.SuppressFinalize(this);
            }
            _currentCount = 0;
        }

        /// <summary>Garbage Collection</summary>
        ~TokenPrivilegeArray()
        {
            Dispose(false);
            _internalPtr = null;
        }
    }
}
