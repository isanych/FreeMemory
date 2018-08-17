// 2009 by NickLowe, version 35.  Via https://processprivileges.codeplex.com/
namespace ProcessPrivileges
{
    using System;
    using System.Diagnostics;
    using System.Runtime.CompilerServices;
    using System.Security.Permissions;

	/// <summary>Extensions for Process</summary>
	public static class ProcessExtensions
    {
		/// <summary>Enable Privileges</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public static TokenPrivilegeArray EnablePrivilege(this AccessTokenHandle accessTokenHandle, params Privilege[] privilege)
        {
            return Privileges.EnablePrivilege(accessTokenHandle, privilege);
        }

		/// <summary>Enable Privileges</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public static TokenPrivilegeArray EnablePrivilege(this Process process, params Privilege[] privilege)
        {
            using (AccessTokenHandle handle = new AccessTokenHandle(process, TokenAccessRights.AdjustPrivileges | TokenAccessRights.Query))
            {
                return handle.EnablePrivilege(privilege);
            }
        }

		/// <summary>Get Access Token</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public static AccessTokenHandle GetAccessTokenHandle(this Process process)
        {
            return process.GetAccessTokenHandle(TokenAccessRights.AllAccess);
        }

		/// <summary>Get Access Token</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public static AccessTokenHandle GetAccessTokenHandle(this Process process, TokenAccessRights tokenAccessRights)
        {
            return new AccessTokenHandle(process, tokenAccessRights);
        }

		/// <summary>What attributes are present for given privilege</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public static PrivilegeAttributes GetPrivilegeAttributes(this AccessTokenHandle accessTokenHandle, Privilege privilege)
        {
            return Privileges.GetPrivilegeAttributes(privilege, accessTokenHandle.GetPrivileges());
        }

		/// <summary>What attributes are present for given privilege</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public static PrivilegeAttributes GetPrivilegeAttributes(this Process process, Privilege privilege)
        {
            return Privileges.GetPrivilegeAttributes(privilege, process.GetPrivileges());
        }

		/// <summary>Get current privileges</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public static System.Collections.Generic.List<PrivilegeAndAttributes> GetPrivileges(this AccessTokenHandle accessTokenHandle)
        {
            return Privileges.GetPrivileges(accessTokenHandle);
        }

		/// <summary>Get current privileges</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
		public static System.Collections.Generic.List<PrivilegeAndAttributes> GetPrivileges(this Process process)
        {
            using (AccessTokenHandle handle = new AccessTokenHandle(process, TokenAccessRights.Query))
            {
                return Privileges.GetPrivileges(handle);
            }
        }

		/// <summary>Get state of given privilege</summary>
		[MethodImpl(MethodImplOptions.Synchronized)]
        public static PrivilegeState GetPrivilegeState(PrivilegeAttributes privilegeAttributes)
        {
            if ((privilegeAttributes & PrivilegeAttributes.Enabled) == PrivilegeAttributes.Enabled)
            {
                return PrivilegeState.Enabled;
            }
            if ((privilegeAttributes & PrivilegeAttributes.Removed) == PrivilegeAttributes.Removed)
            {
                return PrivilegeState.Removed;
            }
            return PrivilegeState.Disabled;
        }

		/// <summary>Get state of given privilege</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public static PrivilegeState GetPrivilegeState(this AccessTokenHandle accessTokenHandle, Privilege privilege)
        {
            return GetPrivilegeState(accessTokenHandle.GetPrivilegeAttributes(privilege));
        }

		/// <summary>Get state of given privilege</summary>
		[MethodImpl(MethodImplOptions.Synchronized), PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public static PrivilegeState GetPrivilegeState(this Process process, Privilege privilege)
        {
            return GetPrivilegeState(process.GetPrivilegeAttributes(privilege));
        }
    }
}

