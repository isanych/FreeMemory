// 2009 by NickLowe, version 35.  Via https://processprivileges.codeplex.com/

namespace ProcessPrivileges
{
    /// <summary>Hold the combined privilege and attribute value</summary>
    public struct PrivilegeAndAttributes
    {
        /// <summary>the privilege</summary>
        public readonly Privilege Privilege;

        /// <summary>the Attribute value</summary>
        public readonly PrivilegeAttributes Attributes;

        /// <summary>Instansiate</summary>
        /// <param name="Privilege"></param>
        /// <param name="Attributes"></param>
        public PrivilegeAndAttributes(Privilege Privilege, PrivilegeAttributes Attributes)
        {
            this.Privilege = Privilege;
            this.Attributes = Attributes;
        }
    } // public struct PrivilegeAndAttributes 
} // namespace ProcessPrivileges

