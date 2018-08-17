// 2009 by NickLowe, version 35.  Via https://processprivileges.codeplex.com/
namespace ProcessPrivileges
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Text;

    internal static class Privileges
    {
        internal static readonly SortedList<Privilege, Luid> luidList = new SortedList<Privilege, Luid>((int)Privilege._MaxInvalid);
        internal static readonly SortedList<string, Privilege> privilegeConstants;

        static Privileges()
        {
            privilegeConstants = new SortedList<string, Privilege>((int)Privilege._MaxInvalid, StringComparer.InvariantCulture) {
                { "SeAssignPrimaryTokenPrivilege", Privilege.AssignPrimaryToken },
                { "SeAuditPrivilege", Privilege.Audit },
                { "SeBackupPrivilege", Privilege.Backup },
                { "SeChangeNotifyPrivilege", Privilege.ChangeNotify },
                { "SeCreateGlobalPrivilege", Privilege.CreateGlobal },
                { "SeCreatePagefilePrivilege", Privilege.CreatePageFile },
                { "SeCreatePermanentPrivilege", Privilege.CreatePermanent },
                { "SeCreateSymbolicLinkPrivilege", Privilege.CreateSymbolicLink },
                { "SeCreateTokenPrivilege", Privilege.CreateToken },
                { "SeDebugPrivilege", Privilege.Debug },
                { "SeEnableDelegationPrivilege", Privilege.EnableDelegation },
                { "SeImpersonatePrivilege", Privilege.Impersonate },
                { "SeIncreaseBasePriorityPrivilege", Privilege.IncreaseBasePriority },
                { "SeIncreaseQuotaPrivilege", Privilege.IncreaseQuota },
                { "SeIncreaseWorkingSetPrivilege", Privilege.IncreaseWorkingSet },
                { "SeLoadDriverPrivilege", Privilege.LoadDriver },
                { "SeLockMemoryPrivilege", Privilege.LockMemory },
                { "SeMachineAccountPrivilege", Privilege.MachineAccount },
                { "SeManageVolumePrivilege", Privilege.ManageVolume },
                { "SeProfileSingleProcessPrivilege", Privilege.ProfileSingleProcess },
                { "SeRelabelPrivilege", Privilege.Relabel },
                { "SeRemoteShutdownPrivilege", Privilege.RemoteShutdown },
                { "SeRestorePrivilege", Privilege.Restore },
                { "SeSecurityPrivilege", Privilege.Security },
                { "SeShutdownPrivilege", Privilege.Shutdown },
                { "SeSyncAgentPrivilege", Privilege.SyncAgent },
                { "SeSystemEnvironmentPrivilege", Privilege.SystemEnvironment },
                { "SeSystemProfilePrivilege", Privilege.SystemProfile },
                { "SeSystemtimePrivilege", Privilege.SystemTime },
                { "SeTakeOwnershipPrivilege", Privilege.TakeOwnership },
                { "SeTimeZonePrivilege", Privilege.TimeZone },
                { "SeTcbPrivilege", Privilege.TrustedComputerBase },
                { "SeTrustedCredManAccessPrivilege", Privilege.TrustedCredentialManagerAccess },
                { "SeUndockPrivilege", Privilege.Undock },
                { "SeUnsolicitedInputPrivilege", Privilege.UnsolicitedInput }
            };
        }

        private static void AdjustPrivilege(AccessTokenHandle accessTokenHandle, PrivilegeAttributes privilegeAttributes, params Luid[] luid)
        {
            var nArray = new TokenPrivilegeArray((uint)luid.Length);

            for (var i = 0; i < luid.Length; i++)
            {
                var v = new LuidAndAttributes
                {
                    Attributes = privilegeAttributes,
                    Luid = luid[i]
                };
                nArray[(uint)i] = v;
            }

            NativeMethods.AdjustTokenPrivileges(accessTokenHandle, false, nArray);
        }

        private static void AdjustPrivilege(AccessTokenHandle accessTokenHandle, PrivilegeAttributes privilegeAttributes, params Privilege[] privilege)
        {
            AdjustPrivilege(accessTokenHandle, privilegeAttributes, GetLuid(privilege));
        }

        internal static void DisablePrivilege(AccessTokenHandle accessTokenHandle, params Privilege[] privilege)
        {
            AdjustPrivilege(accessTokenHandle, PrivilegeAttributes.Disabled, privilege);
        }

        internal static void EnablePrivilege(AccessTokenHandle accessTokenHandle, params Privilege[] privilege)
        {
            AdjustPrivilege(accessTokenHandle, PrivilegeAttributes.Enabled, privilege);
        }

        private static Luid[] GetLuid(params Privilege[] privilege)
        {
            var result = new Luid[privilege.Length];

            for (var i = 0; i < privilege.Length; i++)
            {
                if (luidList.ContainsKey(privilege[i]))
                {
                    result[i] = luidList[privilege[i]];
                }
                else
                {
                    var luid = new Luid();
                    var pos = privilegeConstants.IndexOfValue(privilege[i]);

                    if (!NativeMethods.LookupPrivilegeValue(string.Empty, privilegeConstants.Keys[pos], ref luid))
                    {
                        throw new Win32Exception();
                    }

                    luidList.Add(privilege[i], luid);
                    result[i] = luid;
                }
            }
            return result;
        }

        private static Luid GetLuid(Privilege privilege)
        {
            if (luidList.ContainsKey(privilege))
            {
                return luidList[privilege];
            }
            var luid = new Luid();

            if (!NativeMethods.LookupPrivilegeValue(string.Empty, privilegeConstants.Keys[privilegeConstants.IndexOfValue(privilege)], ref luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            luidList.Add(privilege, luid);
            return luid;
        }

        internal static PrivilegeAttributes GetPrivilegeAttributes(Privilege privilege, List<PrivilegeAndAttributes> Lst)
        {
            foreach (var c in Lst)
            {
                if (c.Privilege == privilege)
                {
                    return c.Attributes;
                }
            }

            GetLuid(privilege);
            return PrivilegeAttributes.Removed;
        }

        private static string GetPrivilegeName(Luid luid)
        {
            var name = new StringBuilder(256);
            var nameLength = name.Capacity;

            if (!NativeMethods.LookupPrivilegeName(string.Empty, ref luid, name, ref nameLength))
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 0x7a && nameLength > 0 && nameLength > name.Capacity)
                {
                    name.Capacity = nameLength;
                    if (!NativeMethods.LookupPrivilegeName(string.Empty, ref luid, name, ref nameLength))
                    {
                        throw new Win32Exception();
                    }
                }
                else
                {
                    throw new Win32Exception(error);
                }
            }
            return name.ToString();
        }

        internal static List<PrivilegeAndAttributes> GetPrivileges(AccessTokenHandle accessTokenHandle)
        {
            var tokenPrivileges = GetTokenPrivileges(accessTokenHandle);
            var length = tokenPrivileges.Length;
            var list = new List<PrivilegeAndAttributes>(length);

            for (var i = 0; i < length; i++)
            {
                var attributes = tokenPrivileges[i];
                var privilegeName = GetPrivilegeName(attributes.Luid);

                if (privilegeConstants.ContainsKey(privilegeName))
                {
                    list.Add(new PrivilegeAndAttributes(privilegeConstants[privilegeName], attributes.Attributes));
                }
            }
            return list;
        }

        private static unsafe LuidAndAttributes[] GetTokenPrivileges(AccessTokenHandle accessTokenHandle)
        {
            var size = (int)((uint)Privilege._MaxInvalid * StaticInfo.LuidAndAttributes_Size);
            var orig = size;
            var ptr = Marshal.AllocHGlobal(size);
            LuidAndAttributes[] result = null;

            try
            {
                if (!NativeMethods.GetTokenInformation(accessTokenHandle, TokenInformationClass.TokenPrivileges, ref ptr, size, out size))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == 0x7a && size > orig)
                    {
                        Marshal.FreeHGlobal(ptr);
                        ptr = Marshal.AllocHGlobal(size);
                        if (!NativeMethods.GetTokenInformation(accessTokenHandle, TokenInformationClass.TokenPrivileges, ref ptr, size, out size))
                        {
                            throw new Win32Exception();
                        }
                    }
                    else
                    {
                        throw new Win32Exception(error);
                    }
                }
                size = size / (int)StaticInfo.LuidAndAttributes_Size;
                result = new LuidAndAttributes[size];
                fixed (void* p = result)
                {
                    NativeMethods.CopyMemory(new IntPtr(p), ptr, (uint)size);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
            return result;
        }

        internal static void RemovePrivilege(AccessTokenHandle accessTokenHandle, params Privilege[] privilege)
        {
            AdjustPrivilege(accessTokenHandle, PrivilegeAttributes.Removed, privilege);
        }
    }
}
