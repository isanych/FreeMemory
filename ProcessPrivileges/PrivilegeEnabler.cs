﻿// 2009 by NickLowe, version 35.  Via https://processprivileges.codeplex.com/
namespace ProcessPrivileges
{
    using System;
	using System.Linq;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Security.Permissions;

	/// <summary>Helper for extending Process' privileges</summary>
	public class PrivilegeEnabler : IDisposable
    {
        private AccessTokenHandle 
			accessTokenHandle;
        private static readonly Dictionary<Process, AccessTokenHandle> 
			accessTokenHandles = new Dictionary<Process, AccessTokenHandle>();
        private bool 
			disposed;
        private bool 
			ownsHandle;
        private Process 
			process;

        private static readonly Dictionary<Privilege, PrivilegeEnabler> 
			sharedPrivileges = new Dictionary<Privilege, PrivilegeEnabler>();

		/// <summary>Instansiate using already existing token</summary>
		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public PrivilegeEnabler(AccessTokenHandle accessTokenHandle)
        {
            this.accessTokenHandle = accessTokenHandle;
        }

		/// <summary>Instansiate for given process</summary>
		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public PrivilegeEnabler(Process process)
        {
            lock (accessTokenHandles)
            {
                if (accessTokenHandles.ContainsKey(process))
                    this.accessTokenHandle = accessTokenHandles[process];
                else
                {
                    this.accessTokenHandle = process.GetAccessTokenHandle(TokenAccessRights.AdjustPrivileges | TokenAccessRights.Query);
                    accessTokenHandles.Add(process, this.accessTokenHandle);
                    this.ownsHandle = true;
                }
            }
            this.process = process;
        }

		/// <summary>Instansiate and enable privileges</summary>
		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public PrivilegeEnabler(AccessTokenHandle accessTokenHandle, params Privilege[] privileges) : this(accessTokenHandle)
        {
            foreach (Privilege privilege in privileges)
                this.EnablePrivilege(privilege);
        }

		/// <summary>Instansiate and enable privileges</summary>
		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public PrivilegeEnabler(Process process, params Privilege[] privileges) : this(process)
        {
            foreach (Privilege privilege in privileges)
                this.EnablePrivilege(privilege);
        }

		/// <summary>Free up memory prior to garbage collection</summary>
		[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
        public void Dispose()
        {
            Dispose(true);
        }

		/// <summary>enable privilege</summary>
		[PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public void EnablePrivilege(Privilege privilege)
        {
            lock (sharedPrivileges)
            {
                if ((!sharedPrivileges.ContainsKey(privilege) && (this.accessTokenHandle.GetPrivilegeState(privilege) == PrivilegeState.Disabled)))
                {
					try
					{
						this.accessTokenHandle.EnablePrivilege(privilege);
						sharedPrivileges.Add(privilege, this);
					}
					catch { }
                }
            }
		}

		/// <summary>Garbage collect</summary>
		~PrivilegeEnabler()
        {
            Dispose(true);
        }

		/// <summary>Follow Microsoft's Dispose pattern</summary>
		[PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
		protected virtual void Dispose(bool IncludeManaged)
        {
			if (IncludeManaged)
			{
				if (!this.disposed)
				{
					lock (sharedPrivileges)
					{
						if (this.ownsHandle)
						{
							this.accessTokenHandle.Dispose();
							lock (this.accessTokenHandle)
							{
								accessTokenHandles.Remove(this.process);
							}
						}
						this.accessTokenHandle = null;
						this.ownsHandle = false;
						this.process = null;
						this.disposed = true;
					}
				}
				GC.SuppressFinalize(this);
			}
        }
    }
}
