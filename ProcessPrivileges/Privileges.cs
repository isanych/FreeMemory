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
        internal static readonly SortedList<Privilege, Luid>
			luidList = new SortedList<Privilege, Luid>((int)Privilege._MaxInvalid);

		internal static readonly SortedList<string, Privilege> 
			privilegeConstants;

        static Privileges()
        {
            SortedList<string, Privilege>
				Lst = new SortedList<string, Privilege>((int)Privilege._MaxInvalid, StringComparer.InvariantCulture);

			Lst.Add("SeAssignPrimaryTokenPrivilege", Privilege.AssignPrimaryToken);
			Lst.Add("SeAuditPrivilege", Privilege.Audit);
			Lst.Add("SeBackupPrivilege", Privilege.Backup);
			Lst.Add("SeChangeNotifyPrivilege", Privilege.ChangeNotify);
			Lst.Add("SeCreateGlobalPrivilege", Privilege.CreateGlobal);
			Lst.Add("SeCreatePagefilePrivilege", Privilege.CreatePageFile);
			Lst.Add("SeCreatePermanentPrivilege", Privilege.CreatePermanent);
			Lst.Add("SeCreateSymbolicLinkPrivilege", Privilege.CreateSymbolicLink);
			Lst.Add("SeCreateTokenPrivilege", Privilege.CreateToken);
			Lst.Add("SeDebugPrivilege", Privilege.Debug);
			Lst.Add("SeEnableDelegationPrivilege", Privilege.EnableDelegation);
			Lst.Add("SeImpersonatePrivilege", Privilege.Impersonate);
			Lst.Add("SeIncreaseBasePriorityPrivilege", Privilege.IncreaseBasePriority);
			Lst.Add("SeIncreaseQuotaPrivilege", Privilege.IncreaseQuota);
			Lst.Add("SeIncreaseWorkingSetPrivilege", Privilege.IncreaseWorkingSet);
			Lst.Add("SeLoadDriverPrivilege", Privilege.LoadDriver);
			Lst.Add("SeLockMemoryPrivilege", Privilege.LockMemory);
			Lst.Add("SeMachineAccountPrivilege", Privilege.MachineAccount);
			Lst.Add("SeManageVolumePrivilege", Privilege.ManageVolume);
			Lst.Add("SeProfileSingleProcessPrivilege", Privilege.ProfileSingleProcess);
			Lst.Add("SeRelabelPrivilege", Privilege.Relabel);
			Lst.Add("SeRemoteShutdownPrivilege", Privilege.RemoteShutdown);
			Lst.Add("SeRestorePrivilege", Privilege.Restore);
			Lst.Add("SeSecurityPrivilege", Privilege.Security);
			Lst.Add("SeShutdownPrivilege", Privilege.Shutdown);
			Lst.Add("SeSyncAgentPrivilege", Privilege.SyncAgent);
			Lst.Add("SeSystemEnvironmentPrivilege", Privilege.SystemEnvironment);
			Lst.Add("SeSystemProfilePrivilege", Privilege.SystemProfile);
			Lst.Add("SeSystemtimePrivilege", Privilege.SystemTime);
			Lst.Add("SeTakeOwnershipPrivilege", Privilege.TakeOwnership);
			Lst.Add("SeTimeZonePrivilege", Privilege.TimeZone);
			Lst.Add("SeTcbPrivilege", Privilege.TrustedComputerBase);
			Lst.Add("SeTrustedCredManAccessPrivilege", Privilege.TrustedCredentialManagerAccess);
			Lst.Add("SeUndockPrivilege", Privilege.Undock);
			Lst.Add("SeUnsolicitedInputPrivilege", Privilege.UnsolicitedInput);
			privilegeConstants = Lst;
        }

		private static TokenPrivilegeArray AdjustPrivilege(AccessTokenHandle accessTokenHandle, PrivilegeAttributes privilegeAttributes, params Luid[] luid)
        {
			TokenPrivilegeArray
				nArray = new TokenPrivilegeArray((uint)luid.Length);

			for(int i=0; i<luid.Length; i++)
			{
				LuidAndAttributes
					v = new LuidAndAttributes();
				v.Attributes = privilegeAttributes;
				v.Luid = luid[i];
				nArray[(uint)i] = v;
			}

			return NativeMethods.AdjustTokenPrivileges(accessTokenHandle, false, nArray);
        }

		private static TokenPrivilegeArray AdjustPrivilege(AccessTokenHandle accessTokenHandle, PrivilegeAttributes privilegeAttributes, params Privilege[] privilege)
        {
			return AdjustPrivilege(accessTokenHandle, privilegeAttributes, GetLuid(privilege));
        }

		internal static TokenPrivilegeArray DisablePrivilege(AccessTokenHandle accessTokenHandle, params Privilege[] privilege)
        {
			return AdjustPrivilege(accessTokenHandle, PrivilegeAttributes.Disabled, privilege);
        }

		internal static TokenPrivilegeArray EnablePrivilege(AccessTokenHandle accessTokenHandle, params Privilege[] privilege)
        {
			return AdjustPrivilege(accessTokenHandle, PrivilegeAttributes.Enabled, privilege);
        }

		private static Luid[] GetLuid(params Privilege[] privilege)
		{
			Luid[]
				result = new Luid[privilege.Length];

			for(int i=0; i<privilege.Length; i++)
			{
				if (luidList.ContainsKey(privilege[i]))
					result[i] = luidList[privilege[i]];
				else 
				{
					Luid 
						luid = new Luid();
					int
						pos = privilegeConstants.IndexOfValue(privilege[i]);

					if (!NativeMethods.LookupPrivilegeValue(string.Empty, privilegeConstants.Keys[pos], ref luid))
						throw new Win32Exception();
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
            Luid luid = new Luid();

            if (!NativeMethods.LookupPrivilegeValue(string.Empty, privilegeConstants.Keys[privilegeConstants.IndexOfValue(privilege)], ref luid))
                throw new Win32Exception(Marshal.GetLastWin32Error());

			luidList.Add(privilege, luid);
            return luid;
        }

        internal static PrivilegeAttributes GetPrivilegeAttributes(Privilege privilege, List<PrivilegeAndAttributes>Lst)
        {
            foreach (PrivilegeAndAttributes c in Lst)
                if (c.Privilege == privilege)
                    return c.Attributes;

            GetLuid(privilege);
            return PrivilegeAttributes.Removed;
        }

        private static string GetPrivilegeName(Luid luid)
        {
            StringBuilder 
				name = new StringBuilder(256);
            int 
				nameLength = name.Capacity;

			if (!NativeMethods.LookupPrivilegeName(string.Empty, ref luid, name, ref nameLength))
			{
				int
					error = Marshal.GetLastWin32Error();
				if(error==0x7a && nameLength > 0 && nameLength > name.Capacity)
				{
					name.Capacity = nameLength;
					if (!NativeMethods.LookupPrivilegeName(string.Empty, ref luid, name, ref nameLength))
						throw new Win32Exception();
				} else
					throw new Win32Exception(error);
			}
            return name.ToString();
        }

        internal static List<PrivilegeAndAttributes> GetPrivileges(AccessTokenHandle accessTokenHandle)
        {
            LuidAndAttributes[] 
				tokenPrivileges = GetTokenPrivileges(accessTokenHandle);

            int 
				length = tokenPrivileges.Length;

            List<PrivilegeAndAttributes> 
				list = new List<PrivilegeAndAttributes>(length);

            for (int i = 0; i < length; i++)
            {
                LuidAndAttributes 
					attributes = tokenPrivileges[i];
                string 
					privilegeName = GetPrivilegeName(attributes.Luid);

				if (privilegeConstants.ContainsKey(privilegeName))
					list.Add(new PrivilegeAndAttributes(privilegeConstants[privilegeName], attributes.Attributes));
            }
			return list;
        }

        private unsafe static LuidAndAttributes[] GetTokenPrivileges(AccessTokenHandle accessTokenHandle)
        {
			int
				size = (int)((uint)Privilege._MaxInvalid * StaticInfo.LuidAndAttributes_Size),
				orig = size;

			IntPtr
				ptr = Marshal.AllocHGlobal(size);

			LuidAndAttributes[] 
				result = null;

			try
			{
				if (!NativeMethods.GetTokenInformation(accessTokenHandle, TokenInformationClass.TokenPrivileges, ref ptr, size, out size))
				{
					int 
						error = Marshal.GetLastWin32Error();
					if (error == 0x7a && size > orig)
					{
						Marshal.FreeHGlobal(ptr);
						ptr = Marshal.AllocHGlobal((int)size);
						if (!NativeMethods.GetTokenInformation(accessTokenHandle, TokenInformationClass.TokenPrivileges, ref ptr, size, out size))
							throw new Win32Exception();
					} else
						throw new Win32Exception(error);
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

		internal static TokenPrivilegeArray RemovePrivilege(AccessTokenHandle accessTokenHandle, params Privilege[] privilege)
        {
            return AdjustPrivilege(accessTokenHandle, PrivilegeAttributes.Removed, privilege);
        }
    }
}

