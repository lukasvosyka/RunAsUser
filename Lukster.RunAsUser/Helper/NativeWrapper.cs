using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using Microsoft.Win32.SafeHandles;

namespace Lukster.RunAsUser.Helper
{
    /// <summary>
    /// Native win32 methods
    /// </summary>
	internal static class NativeWrapper
	{
		#region Win32 structures
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            [MarshalAs(UnmanagedType.U4)]
            public SidAttributes dwAttributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {
            public uint dwGroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst=20)]
            public SID_AND_ATTRIBUTES[] Groups;
        }

		[StructLayout(LayoutKind.Sequential)]
		public struct PROFILEINFO
		{
			public int dwSize;
			public int dwFlags;
			[MarshalAs(UnmanagedType.LPTStr)]
			public String lpUserName;
			[MarshalAs(UnmanagedType.LPTStr)]
			public String lpProfilePath;
			[MarshalAs(UnmanagedType.LPTStr)]
			public String lpDefaultPath;
			[MarshalAs(UnmanagedType.LPTStr)]
			public String lpServerName;
			[MarshalAs(UnmanagedType.LPTStr)]
			public String lpPolicyPath;
			public IntPtr hProfile;
		}

        [StructLayout(LayoutKind.Sequential)]
        public struct ACCESS_ALLOWED_ACE
        {
            public ACE_HEADER Header;
            public AceAccessMask Mask;
            public uint SidStart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ACE_HEADER
        {
            public AceType AceType;
            public AceFlags AceFlags;
            public ushort AceSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ACL
        {
            public byte AclRevision;
            public byte Sbz1;
            public ushort AclSize;
            public ushort AceCount;
            public ushort Sbz2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ACL_SIZE_INFORMATION
        {
            public uint AceCount;
            public uint AclBytesInUse;
            public uint AclBytesFree;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_DESCRIPTOR
        {
            public byte Revision;
            public byte Sbz1;
            public short Control;
            public IntPtr Owner;
            public IntPtr Group;
            public IntPtr Sacl;
            public IntPtr Dacl;
        }

		[StructLayout(LayoutKind.Sequential)]
		public struct SECURITY_ATTRIBUTES
		{
			public int nLength;
			public IntPtr lpSecurityDescriptor;
			public int bInheritHandle;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public int dwProcessId;
			public int dwThreadId;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct STARTUPINFO
		{
			public Int32 cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public Int32 dwX;
			public Int32 dwY;
			public Int32 dwXSize;
			public Int32 dwYSize;
			public Int32 dwXCountChars;
			public Int32 dwYCountChars;
			public Int32 dwFillAttribute;
			public Int32 dwFlags;
			public Int16 wShowWindow;
			public Int16 cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }
		#endregion

        #region Enumerations
        #region LogonType
        public enum LogonType : int
		{
			/// <summary>
			/// This logon type is intended for users who will be interactively using the computer, such as a user being logged on  
			/// by a terminal server, remote shell, or similar process.
			/// This logon type has the additional expense of caching logon information for disconnected operations; 
			/// therefore, it is inappropriate for some client/server applications,
			/// such as a mail server.
			/// </summary>
			LOGON32_LOGON_INTERACTIVE = 2,

			/// <summary>
			/// This logon type is intended for high performance servers to authenticate plaintext passwords.

			/// The LogonUser function does not cache credentials for this logon type.
			/// </summary>
			LOGON32_LOGON_NETWORK = 3,

			/// <summary>
			/// This logon type is intended for batch servers, where processes may be executing on behalf of a user without 
			/// their direct intervention. This type is also for higher performance servers that process many plaintext
			/// authentication attempts at a time, such as mail or Web servers. 
			/// The LogonUser function does not cache credentials for this logon type.
			/// </summary>
			LOGON32_LOGON_BATCH = 4,

			/// <summary>
			/// Indicates a service-type logon. The account provided must have the service privilege enabled. 
			/// </summary>
			LOGON32_LOGON_SERVICE = 5,

			/// <summary>
			/// This logon type is for GINA DLLs that log on users who will be interactively using the computer. 
			/// This logon type can generate a unique audit record that shows when the workstation was unlocked. 
			/// </summary>
			LOGON32_LOGON_UNLOCK = 7,

			/// <summary>
			/// This logon type preserves the name and password in the authentication package, which allows the server to make 
			/// connections to other network servers while impersonating the client. A server can accept plaintext credentials 
			/// from a client, call LogonUser, verify that the user can access the system across the network, and still 
			/// communicate with other servers.
			/// NOTE: Windows NT:  This value is not supported. 
			/// </summary>
			LOGON32_LOGON_NETWORK_CLEARTEXT = 8,

			/// <summary>
			/// This logon type allows the caller to clone its current token and specify new credentials for outbound connections.
			/// The new logon session has the same local identifier but uses different credentials for other network connections. 
			/// NOTE: This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
			/// NOTE: Windows NT:  This value is not supported. 
			/// </summary>
			LOGON32_LOGON_NEW_CREDENTIALS = 9,
		}
		#endregion

		#region LogonProvider
		public enum LogonProvider : int
		{
			/// <summary>
			/// Use the standard logon provider for the system. 
			/// The default security provider is negotiate, unless you pass NULL for the domain name and the user name 
			/// is not in UPN format. In this case, the default provider is NTLM. 
			/// NOTE: Windows 2000/NT:   The default security provider is NTLM.
			/// </summary>
			LOGON32_PROVIDER_DEFAULT = 0,
		}
		#endregion

		#region ProcessAccessFlags
		[Flags]
		public enum ProcessAccessFlags : uint
		{
			All = 0x001F0FFF,
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VMOperation = 0x00000008,
			VMRead = 0x00000010,
			VMWrite = 0x00000020,
			DupHandle = 0x00000040,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			Synchronize = 0x00100000
		}
		#endregion

        #region HeapAllocFlags
        public enum HeapAllocFlags : uint
        {
            /*
             * Serialized access will not be used for this allocation. For more information, see Remarks.
             * To ensure that serialized access is disabled for all calls to this function, specify HEAP_NO_SERIALIZE in the call to HeapCreate. In this case, it is not necessary to additionally specify HEAP_NO_SERIALIZE in this function call.
             * This value should not be specified when accessing the process's default heap. The system may create additional threads within the application's process, such as a CTRL+C handler, that simultaneously access the process's default heap.
             */
            HEAP_NO_SERIALIZE = 0x00000001,
            /*
             * The system will raise an exception to indicate a function failure, such as an out-of-memory condition, instead of returning NULL.
             * To ensure that exceptions are generated for all calls to this function, specify HEAP_GENERATE_EXCEPTIONS in the call to HeapCreate. 
             * In this case, it is not necessary to additionally specify HEAP_GENERATE_EXCEPTIONS in this function call.
             */
            HEAP_GENERATE_EXCEPTIONS = 0x00000004,
            /*
             * The allocated memory will be initialized to zero. Otherwise, the memory is not initialized to zero.
             */
            HEAP_ZERO_MEMORY = 0x00000008
        }
        #endregion

        #region TokenInformationClass
        public enum TokenInformationClass
        {
            /// <summary>
            /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
            /// </summary>
            TokenUser = 1,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
            /// </summary>
            TokenGroups,

            /// <summary>
            /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
            /// </summary>
            TokenPrivileges,

            /// <summary>
            /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
            /// </summary>
            TokenOwner,

            /// <summary>
            /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
            /// </summary>
            TokenPrimaryGroup,

            /// <summary>
            /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
            /// </summary>
            TokenDefaultDacl,

            /// <summary>
            /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
            /// </summary>
            TokenSource,

            /// <summary>
            /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
            /// </summary>
            TokenType,

            /// <summary>
            /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
            /// </summary>
            TokenImpersonationLevel,

            /// <summary>
            /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
            /// </summary>
            TokenStatistics,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
            /// </summary>
            TokenRestrictedSids,

            /// <summary>
            /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token. 
            /// </summary>
            TokenSessionId,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
            /// </summary>
            TokenGroupsAndPrivileges,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenSessionReference,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            /// </summary>
            TokenSandBoxInert,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenAuditPolicy,

            /// <summary>
            /// The buffer receives a TOKEN_ORIGIN value. 
            /// </summary>
            TokenOrigin,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
            /// </summary>
            TokenElevationType,

            /// <summary>
            /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
            /// </summary>
            TokenLinkedToken,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
            /// </summary>
            TokenElevation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            /// </summary>
            TokenHasRestrictions,

            /// <summary>
            /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
            /// </summary>
            TokenAccessInformation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            /// </summary>
            TokenVirtualizationAllowed,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            /// </summary>
            TokenVirtualizationEnabled,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level. 
            /// </summary>
            TokenIntegrityLevel,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            /// </summary>
            TokenUIAccess,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
            /// </summary>
            TokenMandatoryPolicy,

            /// <summary>
            /// The buffer receives the token's logon security identifier (SID).
            /// </summary>
            TokenLogonSid,

            /// <summary>
            /// The maximum value for this enumeration
            /// </summary>
            MaxTokenInfoClass
        }
        #endregion

        #region SecurityInformation
        public enum SecurityInformation : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            LABEL_SECURITY_INFORMATION = 0x00000010,

            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
        }
        #endregion

        #region SidAttributes
        public enum SidAttributes : uint
        {
            /*
             * The SID cannot have the SE_GROUP_ENABLED attribute cleared 
             * by a call to the AdjustTokenGroups function. However, you can 
             * use the CreateRestrictedToken function to convert a mandatory 
             * SID to a deny-only SID.
             */
            SE_GROUP_MANDATORY = 0x00000001,
            /*
             * The SID is enabled by default.
             */
            SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
            /*
             * The SID is enabled for access checks. When the system performs 
             * an access check, it checks for access-allowed and access-denied 
             * access control entries (ACEs) that apply to the SID.
             * A SID without this attribute is ignored during an access check 
             * unless the SE_GROUP_USE_FOR_DENY_ONLY attribute is set.
             */
            SE_GROUP_ENABLED = 0x00000004,
            /*
             * The SID identifies a group account for which the user of the 
             * token is the owner of the group, or the SID can be assigned as 
             * the owner of the token or objects.
             */
            SE_GROUP_OWNER = 0x00000008,
            /*
             * The SID is a deny-only SID in a restricted token. When the system 
             * performs an access check, it checks for access-denied ACEs that 
             * apply to the SID; it ignores access-allowed ACEs for the SID. 
             * If this attribute is set, SE_GROUP_ENABLED is not set, and the 
             * SID cannot be reenabled.
             */
            SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,
            /*
             * TBD
             */
            SE_GROUP_INTEGRITY = 0x00000020,
            /*
             * TBD
             */
            SE_GROUP_INTEGRITY_ENABLED = 0x00000040,
            /*
             * The SID identifies a domain-local group.
             */
            SE_GROUP_RESOURCE = 0x20000000,
            /*
             * The SID is a logon SID that identifies the logon session associated 
             * with an access token.
             */
            SE_GROUP_LOGON_ID = 0xC0000000
        }
        #endregion

        #region AceType
        public enum AceType : byte
        {
            ACCESS_ALLOWED_ACE_TYPE = 0x0,
            ACCESS_DENIED_ACE_TYPE = 0x1,
            SYSTEM_AUDIT_ACE_TYPE = 0x2,
            SYSTEM_ALARM_ACE_TYPE = 0x3,

            ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x4,

            ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x5,
            ACCESS_DENIED_OBJECT_ACE_TYPE = 0x6,
            SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x7,
            SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x8,

            ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x9,
            ACCESS_DENIED_CALLBACK_ACE_TYPE = 0xA,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB,
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0xC,
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0xD,
            SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0xE,
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0xF,
            SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10,

            SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11,
        }
        #endregion

        #region AceFlags
        public enum AceFlags : byte
        {
            OBJECT_INHERIT_ACE = 0x1,
            CONTAINER_INHERIT_ACE = 0x2,
            NO_PROPAGATE_INHERIT_ACE = 0x4,
            INHERIT_ONLY_ACE = 0x8,
            INHERITED_ACE = 0x10,
            VALID_INHERIT_FLAGS = 0x1F,
            SUCCESSFUL_ACCESS_ACE_FLAG = 0x40,
            FAILED_ACCESS_ACE_FLAG = 0x80
        }
        #endregion

        #region AceAccessMask
        public enum AceAccessMask : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000f0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001f0000,
            SPECIFIC_RIGHTS_ALL = 0x0000ffff,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            DESKTOP_ALL = (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_HOOKCONTROL |
                           DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK | DESKTOP_ENUMERATE |
                           DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP),
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = (WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | WINSTA_ACCESSCLIPBOARD |
                                 WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES | WINSTA_ACCESSGLOBALATOMS |
                                 WINSTA_EXITWINDOWS | WINSTA_ENUMERATE | WINSTA_READSCREEN)
        }
        #endregion

        #region AclSizeInformation
        public enum AclInformationClass
        {
            AclRevisionInformation = 1,
            AclSizeInformation
        }
        #endregion
        #endregion

        #region Constants
        #region GetUserObjectSecurity constants
        public const uint SECURITY_DESCRIPTOR_REVISION = 1;
        public const uint ACL_REVISION = 2;
        public const uint MAXDWORD = 0xffffffff;
        #endregion

        #region OpenProcessToken AccessTypes constants
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
		public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
		public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
		public const UInt32 TOKEN_DUPLICATE = 0x0002;
		public const UInt32 TOKEN_IMPERSONATE = 0x0004;
		public const UInt32 TOKEN_QUERY = 0x0008;
		public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
		public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
		public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
		public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
		public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
		public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
		public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
			TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
			TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
			TOKEN_ADJUST_SESSIONID);

        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_TCB_NAME = "SeTcbPrivilege";

        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
		#endregion

        #region WaitForSingleObject results constants
        public const UInt32 WAIT_OBJECT_0 = 0x0;
		public const UInt32 WAIT_ABANDONED = 0x80;
		public const UInt32 WAIT_TIMEOUT = 0x102;
		#endregion
        #endregion

        #region DllImports
        #region WindowStation Desktop functions
        #region OpenWindowStation
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("user32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern SafeWindowStationHandle OpenWindowStation(
            [MarshalAs(UnmanagedType.LPTStr)]
            string lpszWinSta,
            [MarshalAs(UnmanagedType.Bool)]
            bool fInherit,
            AceAccessMask dwDesiredAccess
            );
        #endregion

        #region CloseWindowStation
        [return: MarshalAs(UnmanagedType.Bool)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("user32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CloseWindowStation(
            IntPtr hWinsta
            );
        #endregion

        #region OpenDesktop
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern SafeDesktopHandle OpenDesktop(
            string lpszDesktop, 
            uint dwFlags,
            bool fInherit, 
            AceAccessMask dwDesiredAccess
            );
        #endregion

        #region CloseDesktop
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CloseDesktop(
            IntPtr hDesktop
            );
        #endregion

        #region GetProcessWindowStation
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeWindowStationHandle GetProcessWindowStation();
        #endregion

        #region SetProcessWindowStation
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetProcessWindowStation(
            IntPtr hWinSta
            );
        #endregion
        #endregion

        #region GetTokenInformation
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr hToken,
            TokenInformationClass tokenInfoDesire,
            IntPtr pTokenInfo, // a pointer to a win32 struct depending on the value in tokenInfoDesire
            uint dwTokenInfoLength,
            out uint dwTokenResultLength
            );
        #endregion

        #region LookupPrivilegeValue
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName, 
            string lpName,
            out LUID lpLuid
            );
        #endregion

        #region AdjustTokenPrivilege
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr hToken,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLength,
            IntPtr pPreviousState,
            int ReturnLength
            );
        #endregion

        #region GetAclInformation
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetAclInformation(
            IntPtr pAcl,
            IntPtr pAclInformation,
            uint deAclInformationLength,
            AclInformationClass dwAclInformationClass
            );
        #endregion

        #region GetUserObjectSecurity
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetUserObjectSecurity(
            IntPtr hObject,
            [In] ref SecurityInformation pSecurityInfoDesire,
            IntPtr pSecurityDescriptor,
            uint dwLength,
            out uint dwLengthNeeded
            );
        #endregion

        #region SetUserObjectSecurity
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetUserObjectSecurity(
            IntPtr hObject,
            [In] ref SecurityInformation pSecurityInfoDesire, 
            IntPtr pSecurityDescriptor
            );
        #endregion

        #region InitializeSecurityDescriptor
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool InitializeSecurityDescriptor(
            IntPtr pSecurityDescriptor, 
            uint dwRevision
            );
        #endregion

        #region GetSecurityDescriptorDacl
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            out bool daclPresent,
            ref IntPtr pDacl,
            out bool daclDefaulted
            );
        #endregion

        #region SetSecurityDescriptorDacl
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor, 
            bool daclPresent, 
            IntPtr pDacl, 
            bool daclDefaulted);
        #endregion

        #region InitializeAcl
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool InitializeAcl(
            IntPtr pAcl,
            uint dwAclLength, 
            uint dwAclRevision
            );
        #endregion

        #region GetAce
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetAce(
            IntPtr pAcl, 
            uint dwAceIndex, 
            ref IntPtr pAce
            );
        #endregion

        #region AddAce
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AddAce(
            IntPtr pAcl, 
            uint dwAceRevision, 
            uint dwStartingAceIndex, 
            IntPtr pAceList, 
            uint nAceListLength
            );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AddAce(
            IntPtr pAcl,
            uint dwAceRevision,
            uint dwStartingAceIndex,
            ref ACCESS_ALLOWED_ACE pAceList,
            uint nAceListLength
            );
        #endregion

        #region AddAccessAllowedAce
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AddAccessAllowedAce(
            IntPtr pAcl, 
            uint dwAceRevision, 
            AceAccessMask AccessMask, 
            IntPtr pSid);
        #endregion

        #region GetLengthSid
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint GetLengthSid(
            IntPtr pSid
            );
        #endregion

        #region CopySid
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CopySid(
            uint nDestinationSidLength, 
            IntPtr pDestinationSid,
            IntPtr pSourceSid
            );
        #endregion

        #region HeapAlloc
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr HeapAlloc(
            IntPtr hHeap, 
            HeapAllocFlags dwFlags, 
            uint dwBytes
            );
        #endregion

        #region HeapFree
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool HeapFree(
            IntPtr hHeap,
            uint dwFlags, 
            IntPtr lpMem
            );
        #endregion

        #region GetProcessHeap
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessHeap();
        #endregion

        #region GetSystemMetrics
        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
		public static extern int GetSystemMetrics(
            int nIndex
            );
		#endregion

		#region LogonUser
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool LogonUser(
			string lpszUsername,
			string lpszDomain,
			string lpszPassword,
			LogonType dwLogonType,
			LogonProvider dwLogonProvider,
			out IntPtr phToken
			);
		#endregion

		#region LoadUserProfile
		[DllImport("userenv.dll", SetLastError=true)]
		public static extern bool LoadUserProfile(
			IntPtr hToken, 
			ref PROFILEINFO lpProfileInfo
			);
		#endregion

		#region UnloadUserProfile
		[DllImport("userenv.dll", SetLastError=true)]
		public static extern bool UnloadUserProfile(
            IntPtr hToken, 
            IntPtr hProfile
            );
		#endregion

		#region WaitForSingleObject
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern Int32 WaitForSingleObject(
			IntPtr handle,
			UInt32 timeout);
		#endregion

		#region CreateEnvironmentBlock
		[DllImport("userenv.dll", SetLastError = true)]
		public static extern bool CreateEnvironmentBlock(
			out IntPtr lpEnvironmentBlock,
			IntPtr hToken,
			bool bInherit
			);
		#endregion

		#region DestroyEnvironmentBlock
		[DllImport("userenv.dll", SetLastError = true)]
		public static extern bool DestroyEnvironmentBlock(
			IntPtr lpEnvironmentBlock
			);
		#endregion

		#region OpenProcess
        [DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(
			ProcessAccessFlags dwDesiredAccess,
			[MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
			uint dwProcessId
			);
		#endregion

		#region OpenProcessToken
		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle,
			UInt32 DesiredAccess, 
			out IntPtr TokenHandle
			);
		#endregion

		#region TerminateProcess
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool TerminateProcess(
			IntPtr hProcess,
			uint exitCode
			);
		#endregion

		#region GetExitCodeProcess
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool GetExitCodeProcess(
			IntPtr hProcess,
			out int lpExitCode
			);
		#endregion

		#region CloseHandle
		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CloseHandle(
			IntPtr hObject
			);
		#endregion

		#region WaitForInputIdle
        [DllImport("user32.dll", SetLastError = true)]
		public static extern uint WaitForInputIdle(
			IntPtr hProcess, 
			uint dwMilliseconds
			);
		#endregion

		#region ImpersonateLoggedOnUser
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern int ImpersonateLoggedOnUser(
			IntPtr hToken
			);
		#endregion

        #region RevertToSelf
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
        #endregion

        #region CeateProcessAsUser
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool CreateProcessAsUser(
			IntPtr hToken,
			string lpApplicationName,
			[In] StringBuilder lpCommandLine,
			ref SECURITY_ATTRIBUTES lpProcessAttributes,
			ref SECURITY_ATTRIBUTES lpThreadAttributes,
			bool bInheritHandles,
			uint dwCreationFlags,
			IntPtr lpEnvironment,
			string lpCurrentDirectory,
			ref STARTUPINFO lpStartupInfo,
			out PROCESS_INFORMATION lpProcessInformation
			);
		#endregion
        #endregion

        #region Helper classes
        public sealed class SafeWindowStationHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeWindowStationHandle()
                : base(true)
            {
            }

            protected override bool ReleaseHandle()
            {
                return NativeWrapper.CloseWindowStation(handle);
            }
        }

        public sealed class SafeDesktopHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeDesktopHandle()
                : base(true)
            {
            }

            protected override bool ReleaseHandle()
            {
                return NativeWrapper.CloseDesktop(handle);
            }
        }
        #endregion
    }
}
