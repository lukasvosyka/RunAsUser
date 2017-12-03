using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Security;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Lukster.RunAsUser.Logging;
using Lukster.RunAsUser.Helper;
using System.Timers;
using System.Threading;
using System.Security.Principal;
using System.Net;
using Microsoft.Win32;
using System.ComponentModel;

namespace Lukster.RunAsUser.IO
{
	/// <summary>
	/// This class encapulates the functionallity of execting a command under different user credentials.
	/// This works similar to the "runas" tool that is shipped with windows or similar to the .Net 2.0 framework
	/// class <see cref="System.Diagnostics.Process">Process</see>.
	/// The additional functionality is that it uses per default the currently logged on user.
	/// The access token that is provided must have following priviledges to successfully start the process:
	/// <ul>
	/// <li>TOKEN_QUERY</li>
	/// <li>TOKEN_ASSIGN_PRIMARY</li>
	/// </ul>
	/// </summary>
	public sealed class ProcessStart : IDisposable
	{
		#region Member
		// used log
		private static Logger log = LogFactory.GetLogger(typeof(ProcessStart));
		// member variables
		private IntPtr hAccessToken;
		private IntPtr hUserProfileRegToken;
		private IntPtr hEnvironmentBlockHandle;
        private NativeWrapper.SafeWindowStationHandle hCurrentWinSta;
        private NativeWrapper.SafeWindowStationHandle hWinSta;
        private NativeWrapper.SafeDesktopHandle hDesktop;
        private IntPtr pSid;

		private bool createNoWindowFlag;
		private bool? useInteractiveDesktopFlag;
		private bool loadUserProfileFlag;
		private uint processTimeout;
		private ProcessTimeoutAction processTimeoutAction;

		private string processCredUsername;
		private string processCredPassword;
		private string processCredDomain;
		private string workingDirectory;
		private bool closeAccessToken;
		#endregion

		#region .ctor
		public ProcessStart(IntPtr hAccessToken) 
			: this(hAccessToken, false)
		{
		}

		public ProcessStart(IntPtr hAccessToken, bool closeHandle)
		{
			if (hAccessToken == IntPtr.Zero)
				throw new ArgumentException("hAccessToken");

			this.hAccessToken = hAccessToken;
			this.closeAccessToken = closeHandle;
		}

		public ProcessStart(string userName, string userPassword)
			: this(userName, userPassword, null)
		{
		}

		public ProcessStart(string userName, string userPassword, string domain)
		{
			if (string.IsNullOrEmpty(userName))
				throw new ArgumentNullException("userName");

			this.processCredDomain = domain;
			this.processCredUsername = userName;
			this.processCredPassword = userPassword;
			this.closeAccessToken = true;
		}
		#endregion

		#region Properties
		/// <summary>
		/// Gets or sets a flag indicating if the new process should create a window or not. Default is false.
		/// </summary>
		public bool CreateNoWindow
		{
			get
			{
				return createNoWindowFlag;
			}
			set
			{
				createNoWindowFlag = value;
			}
		}

		/// <summary>
		/// Gets or sets a flag indicating if the executing process should have interaction 
		/// allowed with the desktop or not. Default is true.
		/// </summary>
		public bool Interactive
		{
			get
			{
				return useInteractiveDesktopFlag.HasValue ? useInteractiveDesktopFlag.Value : true;
			}
			set
			{
				useInteractiveDesktopFlag = value;
			}
		}

		/// <summary>
		/// Gets or sets a flag indicating if the user profile should be loaded.
		/// The executing process will than have the user env. variables loaded as well as
		/// its user registry hive in the registry. Default is false.
		/// </summary>
		public bool LoadUserProfile
		{
			get
			{
				return loadUserProfileFlag;
			}
			set
			{
				loadUserProfileFlag = value;
			}
		}

		/// <summary>
		/// Gets or sets the working directory for the process that is going to be started.
		/// The default is the location of the executable file.
		/// </summary>
		public string WorkingDirectory
		{
			get
			{
				
				return workingDirectory;
			}
			set
			{
				workingDirectory = value;
			}
		}

		/// <summary>
		/// Gets or sets the time in milliseconds that is going to be waited for the process to finish gracefully.
		/// </summary>
		public uint ProcessTimeout
		{
			get
			{
				return processTimeout;
			}
			set
			{
				processTimeout = value;
			}
		}

		/// <summary>
		/// Gets or sets the process timeout action that should be triggered if hte process times out.
		/// </summary>
		public ProcessTimeoutAction ProcessTimeoutAction
		{
			get
			{
				return processTimeoutAction;
			}
			set
			{
				processTimeoutAction = value;
			}
		}

		/// <summary>
		/// Returns true if the current system platform runs WinNT
		/// </summary>
		private static bool IsNt
		{
			get
			{
				return (Environment.OSVersion.Platform == PlatformID.Win32NT);
			}
		}
		#endregion

		#region Methods
		/// <summary>
		/// Starts the given commandline. If the username / password properties are set,
		/// the primary access token will be retrieved using the win32 api call to LogonUser.
		/// The calling process must have SE_TCB_NAME and SE_CHANGE_NOTIFY_NAME priviledges enabled.
		/// For local system account these priviledges are enabled per default.
		/// When no username / password informations have been set, the hanle to the access token set by 
		/// constructor is used to start a process. The token that is used MUST be a primary access token, NOT an impersonation token.
		/// To translate an impersonation token to a primary token used win32 api call to DuplicateTokenEx.
		/// Further the calling process must have priviledges set to SE_ASSIGN_PRIMARY_TOKEN_NAME and SE_INCREASE_QUOTA_NAME otherwise the API calls
		/// will result in errors.
		/// </summary>
		/// <param name="commandLine">The command line that is to be executed (f.e. "cmd /c dir > dirlist.txt")</param>
		/// <returns>An error code that signals what happened.</returns>
		public int Start(string commandLine)
		{
            // if we have a username, use win api to log on user and get primary access token
			if (!string.IsNullOrEmpty(processCredUsername))
			{
				log.Debug("Using Win32 API to logon user called [{0}] for domain [{1}]", processCredUsername, string.IsNullOrEmpty(processCredDomain) ? "." : processCredDomain);
				bool logonResult = NativeWrapper.LogonUser(
					processCredUsername,
					string.IsNullOrEmpty(processCredDomain) ? null : processCredDomain,
					processCredPassword,
					NativeWrapper.LogonType.LOGON32_LOGON_INTERACTIVE,
					NativeWrapper.LogonProvider.LOGON32_PROVIDER_DEFAULT,
					out hAccessToken);

				if (!logonResult)
				{
					int win32error = Marshal.GetLastWin32Error();
					log.Fatal("Error occured calling Win32.LogonUser. Win32 error code:[{0}]. Win32 error message: [{1}]", win32error, new Win32Exception(win32error).Message);
					return ExitCodes.LOGON_USER_FAILED;
				}
				else
					log.Debug("Logon succeeded");
				// should the user profile be loaded as well? (quite time consuming)
				if (LoadUserProfile)
				{
					NativeWrapper.PROFILEINFO pi = new NativeWrapper.PROFILEINFO();
					pi.dwSize = Marshal.SizeOf(pi);
					// TODO: check if lpUsername should contain domain name?
					pi.lpUserName = processCredUsername;

					log.Debug("Using Win32 API to load user profile for user [{0}]", processCredUsername);
					// call api
					bool loadProfileResult = NativeWrapper.LoadUserProfile(
						hAccessToken,
						ref pi);

					if (!loadProfileResult)
					{
						int win32error = Marshal.GetLastWin32Error();
						log.Fatal("Error occured calling Win32.LoadUserProfile. Win32 error code:[{0}]. Win32 error message: [{1}].", win32error, new Win32Exception(win32error).Message);
						return ExitCodes.LOAD_USER_PROFILE_FAILED;
					}
					else
						log.Debug("LoadUserProfile succeeded");
					// for final release action as documented in MSDN
					hUserProfileRegToken = pi.hProfile;
				}
			}
			UInt32 creationFlags = 0;
			// create window?
			if (createNoWindowFlag)
			{
				log.Debug("No window will be created for executing process");
				creationFlags |= 0x8000000;
			}

			IntPtr zero = IntPtr.Zero;
			NativeWrapper.SECURITY_ATTRIBUTES processAttributes = new NativeWrapper.SECURITY_ATTRIBUTES();
			NativeWrapper.SECURITY_ATTRIBUTES threadAttributes = new NativeWrapper.SECURITY_ATTRIBUTES();
			NativeWrapper.STARTUPINFO startupInfo = new NativeWrapper.STARTUPINFO();
			NativeWrapper.PROCESS_INFORMATION processInfo = new NativeWrapper.PROCESS_INFORMATION();
			// will make the process be interactive with the current desktop
			if (Interactive)
			{
				log.Debug("Using \"interactive\" desktop mode");
				startupInfo.lpDesktop = @"winsta0\default";

                try
				{
					// additionally set DACL for the target window station and target desktop
					// so first obtain interactive window station
					hWinSta = NativeWrapper.OpenWindowStation(
                        "winsta0",
                        false,
                        NativeWrapper.AceAccessMask.READ_CONTROL |
                        NativeWrapper.AceAccessMask.WRITE_DAC);

					if (hWinSta.IsInvalid)
                    {
                        log.Error("Could not obtain window station 'winsta0'. Cannot continue interactive. Quit.");
                        return ExitCodes.GET_WINDOW_STATION_FAILED;
                    }
                    // save process window station
                    hCurrentWinSta = NativeWrapper.GetProcessWindowStation();
                    if (hCurrentWinSta.IsInvalid)
                    {
                        log.Error("Could not obtain process window station. Cannot continue interactive. Quit.");
                        return ExitCodes.GET_WINDOW_STATION_FAILED;
                    }
                    // before obtaining default desktop we set the process window station
                    if (!NativeWrapper.SetProcessWindowStation(hWinSta.DangerousGetHandle()))
                    {
                        log.Error("Error setting process window station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return ExitCodes.SET_WINDOW_STATION_FAILED;
					}
					hDesktop = NativeWrapper.OpenDesktop(
                        "default",
                        0,
                        false,
                        NativeWrapper.AceAccessMask.READ_CONTROL |
                        NativeWrapper.AceAccessMask.WRITE_DAC |
                        NativeWrapper.AceAccessMask.DESKTOP_READOBJECTS |
                        NativeWrapper.AceAccessMask.DESKTOP_WRITEOBJECTS);
					if (hDesktop.IsInvalid)
                    {
                        log.Error("Error opening default desktop. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return ExitCodes.OPEN_DESKTOP_FAILED;
                    }
                    if (!GetTokenSid(hAccessToken, out pSid))
                    {
                        log.Error("Error getting SID for user [{0}].", new WindowsIdentity(hAccessToken).Name);
                        return ExitCodes.GET_SECURITY_ID_FAILED;
                    }
                    if (!AddSidAceToWindowStation(hWinSta.DangerousGetHandle(), pSid))
                    {
                        log.Error("Error adding ACEs to window station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return ExitCodes.ADD_ACE_TO_WINDOW_STATION_FAILED;
                    }
                    if (!AddSidAceToDesktop(hDesktop.DangerousGetHandle(), pSid))
                    {
                        log.Error("Error adding ACE to desktop. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return ExitCodes.ADD_ACE_TO_DESKTOP_FAILED;
                    }
                }
                catch (Exception ex)
                {
                    log.Error("While preparation for interactive desktop mode a error occured. Exception [{0}].", ex.Message);
                    return ExitCodes.ERROR_WHILE_EXECUTION;
                }
                finally
                {
                    // free buffer to logon SID
                    if (pSid != IntPtr.Zero)
                        CloseTokenSid(pSid);
                    // close handle to window station
                    hWinSta.Close();
                    // close handle to desktop
                    hDesktop.Close();
                }
			}

			log.Debug("Creating environment..");
			bool createEnvironmentResult = NativeWrapper.CreateEnvironmentBlock(
				out hEnvironmentBlockHandle,
				hAccessToken,
				true);

			// if the environment creation failed the program won't terminate
			if (!createEnvironmentResult)
			{
				int win32error = Marshal.GetLastWin32Error();
				log.Error("The environment variables of the specified user could not be created. Win32 error code [{0}]. Win32 error message: [{1}].", win32error, new Win32Exception(win32error).Message);
			}
			else if (IsNt)
			{
				// flag that indicates, that the environment block is unicode encoded
				creationFlags |= 0x400;
				zero = hEnvironmentBlockHandle;
			}

			try
			{
				int errorCode = ExitCodes.OK;
				// this is for safe execution. this region cannot be interrupted in its execution.
				RuntimeHelpers.PrepareConstrainedRegions();
				try
				{
				}
				finally
				{
                    WindowsIdentity wid = new WindowsIdentity(hAccessToken);
					log.Info("Executing command '{0}' with arguments '{1}' under primary access token for user [{2}]", GetExecutable(commandLine), GetArguments(commandLine), wid.Name);
					// impersonate user BEFORE calling createprocessasuser. as MSDN.
					int impersonateUser = NativeWrapper.ImpersonateLoggedOnUser(
										hAccessToken
										);

					// if impersonation fails the program execution won't exit.
					if (impersonateUser == 0)
					{
						int win32error = Marshal.GetLastWin32Error();
						log.Warn("Impersonation of user failed. Propably that is no problem, so execution will continue. Win32 error code [{0}]. Win32 error message: [{1}]", win32error, new Win32Exception(win32error).Message);
					}
					// start process.
					bool result = NativeWrapper.CreateProcessAsUser(
										hAccessToken,
										null,
										new StringBuilder(commandLine),
										ref processAttributes,
										ref threadAttributes,
										false,
										creationFlags,
										zero,
										workingDirectory,
										ref startupInfo,
										out processInfo
										);

                    // after process finish we revert impersonation to ourself
                    if(impersonateUser != 0 && !NativeWrapper.RevertToSelf())
                        log.Warn("Could not revert from impersonation state back to previous credentials. Errors might occur. Win32 error: [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    // if interactive mode was used and we have a valid handle to the previous window station
                    // we must reset the process window station
                    if (Interactive)
                        if (!hCurrentWinSta.IsInvalid)
                            NativeWrapper.SetProcessWindowStation(hCurrentWinSta.DangerousGetHandle());
                        else
                            log.Warn("Could not restore previous process window station, because the handle to it invalidated.");

					// if create process failed we return with error code CREATE_PROCESS_ERROR
					if (!result)
					{
						int win32error = Marshal.GetLastWin32Error();
						log.Fatal("Error using CreateProcessAsUser. Win32 error code: [{0}]. Win32 error message: [{1}]", win32error, new Win32Exception(win32error).Message);
						errorCode = ExitCodes.CREATE_PROCESS_ERROR;
					}
					else // otherwise wait for process to finish within given time
					{
						log.Debug("Process started. [PID:{0}] [Handle:{1}] [Timeout:{2}]", processInfo.dwProcessId, processInfo.hProcess, string.Format("{0} minutes", TimeSpan.FromMilliseconds((double)processTimeout).TotalMinutes.ToString("N")));
						if (processInfo.hProcess == IntPtr.Zero)
							errorCode = ExitCodes.CREATE_PROCESS_NO_PROCESS_HANDLE;
						else if (!WaitOne(processInfo.hProcess, ProcessTimeout))
						{
							// only if kill is conifured we do something.
							if (processTimeoutAction == ProcessTimeoutAction.Kill)
							{
								bool processTerminateResult = NativeWrapper.TerminateProcess(processInfo.hProcess, 0);
								log.Debug("Process termination was {0}", processTerminateResult ? "successful" : string.Format("errornous! Error code: {0}", Marshal.GetLastWin32Error()));
							}
							errorCode = ExitCodes.CREATE_PROCESS_FINISH_TIMED_OUT;
						}

						// get the exit code of the process and write to registry
						int processExitCode = 0;
						bool getExitCodeResult = NativeWrapper.GetExitCodeProcess(processInfo.hProcess, out processExitCode);
						if (!getExitCodeResult)
						{
							int win32error = Marshal.GetLastWin32Error();
							log.Error("The exit code of the program started could not be retrieved! Win32 error code [{0}]. Win32 error message: [{1}].", win32error, new Win32Exception(win32error).Message);
						}
						else
						{
							log.Debug("The exit code of the process started through execution of '{0}' returned [{1}]", commandLine, processExitCode);
							WriteExitCode(commandLine, processExitCode);
						}
						log.Debug("Process finished. [PID:{0}] [Handle:{1}]", processInfo.dwProcessId, processInfo.hProcess);
					}
				}
				return errorCode;
			}
			catch (Exception ex)
			{
				int win32error = Marshal.GetLastWin32Error();
				log.Fatal("Fatal error during start of process [exec: '{0}']. Exception message: '{1}'. Win32 error code: [{2}]. Win32 error message [{3}].", commandLine, ex.Message, win32error, new Win32Exception(win32error).Message);
				return ExitCodes.PROCESS_START_ERROR;
			}
			finally
			{
				if (LoadUserProfile && hUserProfileRegToken != IntPtr.Zero)
					NativeWrapper.UnloadUserProfile(hAccessToken, hUserProfileRegToken);
				if (hEnvironmentBlockHandle != IntPtr.Zero)
					NativeWrapper.DestroyEnvironmentBlock(hEnvironmentBlockHandle);
				if (processInfo.hProcess != IntPtr.Zero)
					NativeWrapper.CloseHandle(processInfo.hProcess);
				if (processInfo.hThread != IntPtr.Zero)
					NativeWrapper.CloseHandle(processInfo.hThread);
			}
		}

        /// <summary>
        /// Retrieves the SID of a access token by calling win32 API.
        /// </summary>
        /// <param name="hAccessToken">A handle to an access token. The token handle must have TOKEN_QUERY access</param>
        /// <param name="pSid">Out parameter with a pointer to the SID structure</param>
        /// <returns>true, if the function succeeds, otherwise false. If false call GetLastWin32Error()</returns>
        private bool GetTokenSid(IntPtr hAccessToken, out IntPtr pSid)
        {
            // set to zero
            pSid = IntPtr.Zero;
            // init function members
            uint tokenInfoLength = 0;
            IntPtr pTokenInformation = IntPtr.Zero;
            NativeWrapper.TOKEN_GROUPS tokenGroups;

            try
            {
                // call GetTokenInformation first time to get resulting length
                // so first time call should fail FOR SURE due to insuficient buffer size
                if (!NativeWrapper.GetTokenInformation(hAccessToken, NativeWrapper.TokenInformationClass.TokenGroups, pTokenInformation, 0, out tokenInfoLength))
                    if (Marshal.GetLastWin32Error() == Win32ErrorCodes.ERROR_INSUFFICIENT_BUFFER)
                    {
                        // in this case we must allocate the right amount of memory within
                        // the process heap to get a buffer for filling
                        pTokenInformation = NativeWrapper.HeapAlloc(
                            NativeWrapper.GetProcessHeap(),
                            NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                            tokenInfoLength);
                        if (pTokenInformation == IntPtr.Zero)
                        {
                            log.Error("Allocation of heap memory failed for token information buffer.");
                            return false;
                        }
                    }
                    else
                    {
                        // this should not happen
                        log.Error("Could not retrieve token informations for the given access token for user [{0}].", new WindowsIdentity(hAccessToken).Name);
                        return false;
                    }
                // call GetTokenInformation second time to get the groups the access token belongs to.
                if (!NativeWrapper.GetTokenInformation(hAccessToken, NativeWrapper.TokenInformationClass.TokenGroups, pTokenInformation, tokenInfoLength, out tokenInfoLength))
                {
                    int win32error = Marshal.GetLastWin32Error();
                    log.Error("Error retrieving token information for access token for user [{0}]. Win32 error: [{1}].", new WindowsIdentity(hAccessToken).Name, new Win32Exception(win32error).Message);
                    return false;
                }

                tokenGroups = (NativeWrapper.TOKEN_GROUPS)Marshal.PtrToStructure(pTokenInformation, typeof(NativeWrapper.TOKEN_GROUPS));
                
                for (int i = 0; i < tokenGroups.dwGroupCount; i++)
                    if ((tokenGroups.Groups[i].dwAttributes & NativeWrapper.SidAttributes.SE_GROUP_LOGON_ID) == NativeWrapper.SidAttributes.SE_GROUP_LOGON_ID)
                    {
                        // get length of SID
                        uint sidLength = NativeWrapper.GetLengthSid(tokenGroups.Groups[i].Sid);
                        // allocate buffer for SID 
                        pSid = NativeWrapper.HeapAlloc(
                            NativeWrapper.GetProcessHeap(),
                            NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                            sidLength);
                        if (pSid == IntPtr.Zero)
                        {
                            log.Error("Allocation of heap memory failed for SID buffer.");
                            return false;
                        } // copy SID to new buffer
                        else if (!NativeWrapper.CopySid(sidLength, pSid, tokenGroups.Groups[i].Sid))
                        {
                            log.Error("Error while internal copying the logon SID for user [{0}]. Win32 error [{1}].", new WindowsIdentity(hAccessToken), new Win32Exception(Marshal.GetLastWin32Error()));
                            return false;
                        }
                        break;
                    }
            }
            catch (Exception ex)
            {
                log.Fatal("An error occured while getting SID for user [{0}]. Excpetion: {1}", new WindowsIdentity(hAccessToken), ex.Message);
                return false;
            }
            finally
            {
                if (pTokenInformation != IntPtr.Zero)
                    NativeWrapper.HeapFree(
                        NativeWrapper.GetProcessHeap(),
                        0,
                        pTokenInformation);
            }
            // without error we can return true
            return true;
        }

        /// <summary>
        /// Closes a valid pointer to a SID structure that resides on the heap.
        /// </summary>
        /// <param name="pSid">Pointer to the SID structure</param>
        private void CloseTokenSid(IntPtr pSid)
        {
            NativeWrapper.HeapFree(
                NativeWrapper.GetProcessHeap(),
                0,
                pSid);
        }

        /// <summary>
        /// Adds new ACEs to the ACL of the window station.
        /// </summary>
        /// <param name="hWindowStation">A valid handle to the window station</param>
        /// <param name="pSid">A valid pointer to a SID structure.</param>
        /// <returns>true, if the function succeeds, otherwise false</returns>
        private bool AddSidAceToWindowStation(IntPtr hWindowStation, IntPtr pSid)
        {
            NativeWrapper.ACCESS_ALLOWED_ACE ace;
            NativeWrapper.ACL_SIZE_INFORMATION aclSizeInfo;
            
            bool daclExists;
            bool daclPresent;
            uint securityDescriptorLength = 0;
            uint newAclLength = 0;
            uint sidLength = NativeWrapper.GetLengthSid(pSid);

            IntPtr pAcl = IntPtr.Zero;
            IntPtr pNewAcl = IntPtr.Zero;
            IntPtr pSd = IntPtr.Zero;
            IntPtr pSdNew = IntPtr.Zero;
            IntPtr pAce = IntPtr.Zero;
            IntPtr pAclSizeInfo = IntPtr.Zero;
            IntPtr pTempAce = IntPtr.Zero;
            IntPtr pSidAce = IntPtr.Zero;

            NativeWrapper.SecurityInformation si = NativeWrapper.SecurityInformation.DACL_SECURITY_INFORMATION;

            try
            {
                // as with GetTokenSid calls GetTokenInformation should fail
                // the first call to GetUserObjectSecurity should fail as well
                // to get the buffer size for the ACL.
                if (!NativeWrapper.GetUserObjectSecurity(hWindowStation, ref si, pSd, securityDescriptorLength, out securityDescriptorLength))
                    if (Marshal.GetLastWin32Error() == Win32ErrorCodes.ERROR_INSUFFICIENT_BUFFER)
                    {
                        pSd = NativeWrapper.HeapAlloc(
                            NativeWrapper.GetProcessHeap(),
                            NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                            securityDescriptorLength);
                        if (pSd == IntPtr.Zero)
                        {
                            log.Error("Allocation of heap memory failed for security descriptor buffer. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }

                        pSdNew = NativeWrapper.HeapAlloc(
                            NativeWrapper.GetProcessHeap(),
                            NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                            securityDescriptorLength);
                        if (pSdNew == IntPtr.Zero)
                        {
                            log.Error("Allocation of heap memory failed for new security descriptor buffer. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }
                    }
                    else
                    {
                        // this should not happen
                        log.Error("Could not retrieve user object security for windows station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return false;
                    }

                // the second call should work for GetUserObjectSecurity
                if (!NativeWrapper.GetUserObjectSecurity(hWindowStation, ref si, pSd, securityDescriptorLength, out securityDescriptorLength))
                {
                    log.Error("Could not retrieve user object security for windows station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // create new DACL
                if (!NativeWrapper.InitializeSecurityDescriptor(pSdNew, NativeWrapper.SECURITY_DESCRIPTOR_REVISION))
                {
                    log.Error("Error initializing security descriptor. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // get DACL from the security descriptor
                if (!NativeWrapper.GetSecurityDescriptorDacl(pSd, out daclPresent, ref pAcl, out daclExists))
                {
                    log.Error("Error requsting DACL from security descriptor. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                
                pAclSizeInfo = NativeWrapper.HeapAlloc(
                    NativeWrapper.GetProcessHeap(),
                    NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                    Convert.ToUInt32(Marshal.SizeOf(typeof(NativeWrapper.ACL_SIZE_INFORMATION))));

                // call only if DACL is not null
                if (pAcl != IntPtr.Zero)
                    if (!NativeWrapper.GetAclInformation(
                        pAcl,
                        pAclSizeInfo,
                        Convert.ToUInt32(Marshal.SizeOf(typeof(NativeWrapper.ACL_SIZE_INFORMATION))),
                        NativeWrapper.AclInformationClass.AclSizeInformation))
                    {
                        log.Error("Error retrieving ACL informations. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return false;
                    }

                // get managed object from pointer
                aclSizeInfo = (NativeWrapper.ACL_SIZE_INFORMATION)Marshal.PtrToStructure(pAclSizeInfo, typeof(NativeWrapper.ACL_SIZE_INFORMATION));

                // compute new DACL length
                newAclLength = aclSizeInfo.AclBytesInUse +
                    (2 * Convert.ToUInt32(Marshal.SizeOf(typeof(NativeWrapper.ACCESS_ALLOWED_ACE)))) +
                    (2 * sidLength) -
                    (2 * sizeof(uint));

                // allocate memory for new DACL
                pNewAcl = NativeWrapper.HeapAlloc(
                    NativeWrapper.GetProcessHeap(),
                    NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                    newAclLength);
                if (pNewAcl == IntPtr.Zero)
                {
                    log.Error("Allocation of heap memory failed for new security descriptor buffer. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }

                // initialize new DACL
                if (!NativeWrapper.InitializeAcl(pNewAcl, newAclLength, NativeWrapper.ACL_REVISION))
                {
                    log.Error("Initialize ACL failed. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                
                // if DACL present copy it to a new DACL
                if (daclPresent)
                    for (uint i = 0; i < aclSizeInfo.AceCount; i++)
                    {
                        // get the ACE
                        if (!NativeWrapper.GetAce(pAcl, i, ref pTempAce))
                        {
                            log.Error("Error while getting ACE. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }

                        NativeWrapper.ACE_HEADER h = (NativeWrapper.ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(NativeWrapper.ACE_HEADER));


                        // add the ACE to the new ACL
                        if (!NativeWrapper.AddAce(
                            pNewAcl,
                            NativeWrapper.ACL_REVISION,
                            NativeWrapper.MAXDWORD,
                            pTempAce,
                            ((NativeWrapper.ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(NativeWrapper.ACE_HEADER))).AceSize))
                        {
                            log.Error("Error appending ACE to the new ACL. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }
                    }
                // add the first ACE to the window station
                ace = new NativeWrapper.ACCESS_ALLOWED_ACE();
                ace.Header = new NativeWrapper.ACE_HEADER();
                ace.Header.AceFlags = NativeWrapper.AceFlags.CONTAINER_INHERIT_ACE |
                                      NativeWrapper.AceFlags.INHERIT_ONLY_ACE |
                                      NativeWrapper.AceFlags.OBJECT_INHERIT_ACE;
                ace.Header.AceType = NativeWrapper.AceType.ACCESS_ALLOWED_ACE_TYPE;
                ace.Header.AceSize = Convert.ToUInt16(
                                        Marshal.SizeOf(ace) +
                                        sidLength -
                                        sizeof(uint));
                ace.Mask = NativeWrapper.AceAccessMask.GENERIC_ALL;
                
                // append newly created ACE to the new ACL
                pAce = NativeWrapper.HeapAlloc(
                    NativeWrapper.GetProcessHeap(),
                    NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                    Convert.ToUInt32(Marshal.SizeOf(ace) + sidLength - sizeof(uint)));
                if (pAce == IntPtr.Zero)
                {
                    log.Error("Allocation of heap memory for creating ACE failed. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // copy first part of ACE
                Marshal.StructureToPtr(ace, pAce, true);
                // copy SID
                pSidAce = new IntPtr(pAce.ToInt32() + Marshal.SizeOf(typeof(NativeWrapper.ACCESS_ALLOWED_ACE)) - sizeof(uint));

                if (!NativeWrapper.CopySid(sidLength, pSidAce, pSid))
                {
                    log.Error("Error copying SID to the ACE Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                if (!NativeWrapper.AddAce(
                    pNewAcl,
                    NativeWrapper.ACL_REVISION,
                    NativeWrapper.MAXDWORD,
                    pAce,
                    ace.Header.AceSize))
                {
                    log.Error("Error adding first ACE to new ACL for Window station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // append second ACE to the new ACL
                ace.Header.AceFlags = NativeWrapper.AceFlags.NO_PROPAGATE_INHERIT_ACE;
                ace.Mask = NativeWrapper.AceAccessMask.WINSTA_ALL_ACCESS;

                // reset pointer
                Marshal.StructureToPtr(ace, pAce, true);
                // copy again SID
                if (!NativeWrapper.CopySid(sidLength, pSidAce, pSid))
                {
                    log.Error("Error copying SID to the ACE Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }

                if (!NativeWrapper.AddAce(
                    pNewAcl,
                    NativeWrapper.ACL_REVISION,
                    NativeWrapper.MAXDWORD,
                    pAce,
                    ace.Header.AceSize))
                {
                    log.Error("Error adding second ACE to new ACL for Window station Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // now set the new ACL for the new security descriptor
                if (!NativeWrapper.SetSecurityDescriptorDacl(pSdNew, true, pNewAcl, false))
                {
                    log.Error("Error setting new security descriptor ACL for window station.");
                    return false;
                }
                if (!NativeWrapper.SetUserObjectSecurity(hWindowStation, ref si, pSdNew))
                {
                    log.Error("Error setting user object security to new security descriptor for window station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
            }
            catch (Exception ex)
            {
                log.Error("Unhandled error while adding SID to window station. Exception [{0}].", ex.Message);
                return false;
            }
            finally
            {
				// this seems to throw an error...
                //if (pTempAce != IntPtr.Zero)
                //    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pTempAce);
                if (pAclSizeInfo != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pAclSizeInfo);
                if (pAce != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pAce);
                if (pNewAcl != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pNewAcl);
                if (pSd != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pSd);
                if (pSdNew != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pSdNew);
            }
            return true;
        }

        /// <summary>
        /// Adds ACEs to the ACL of the desktop.
        /// </summary>
        /// <param name="hDesktop">A valid handle to the desktop</param>
        /// <param name="pSid">A pointer to a SID structure</param>
        /// <returns>true, if the function succeeds, otherwise false</returns>
        private bool AddSidAceToDesktop(IntPtr hDesktop, IntPtr pSid)
        {
            NativeWrapper.ACCESS_ALLOWED_ACE ace;
            NativeWrapper.ACL_SIZE_INFORMATION aclSizeInfo;

            bool daclExists;
            bool daclPresent;
            uint securityDescriptorLength = 0;
            uint newAclLength = 0;
            uint sidLength = NativeWrapper.GetLengthSid(pSid);

            IntPtr pAcl = IntPtr.Zero;
            IntPtr pNewAcl = IntPtr.Zero;
            IntPtr pSd = IntPtr.Zero;
            IntPtr pSdNew = IntPtr.Zero;
            IntPtr pAclSizeInfo = IntPtr.Zero;
            IntPtr pTempAce = IntPtr.Zero;

            NativeWrapper.SecurityInformation si = NativeWrapper.SecurityInformation.DACL_SECURITY_INFORMATION;

            try
            {
                // as with GetTokenSid calls GetTokenInformation should fail
                // the first call to GetUserObjectSecurity should fail as well
                // to get the buffer size for the ACL.
                if (!NativeWrapper.GetUserObjectSecurity(hDesktop, ref si, pSd, securityDescriptorLength, out securityDescriptorLength))
                    if (Marshal.GetLastWin32Error() == Win32ErrorCodes.ERROR_INSUFFICIENT_BUFFER)
                    {
                        pSd = NativeWrapper.HeapAlloc(
                            NativeWrapper.GetProcessHeap(),
                            NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                            securityDescriptorLength);
                        if (pSd == IntPtr.Zero)
                        {
                            log.Error("Allocation of heap memory failed for security descriptor buffer. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }

                        pSdNew = NativeWrapper.HeapAlloc(
                            NativeWrapper.GetProcessHeap(),
                            NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                            securityDescriptorLength);
                        if (pSdNew == IntPtr.Zero)
                        {
                            log.Error("Allocation of heap memory failed for new security descriptor buffer. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }
                    }
                    else
                    {
                        // this should not happen
                        log.Error("Could not retrieve user object security for windows station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return false;
                    }

                // the second call should work for GetUserObjectSecurity
                if (!NativeWrapper.GetUserObjectSecurity(hDesktop, ref si, pSd, securityDescriptorLength, out securityDescriptorLength))
                {
                    log.Error("Could not retrieve user object security for windows station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // create new DACL
                if (!NativeWrapper.InitializeSecurityDescriptor(pSdNew, NativeWrapper.SECURITY_DESCRIPTOR_REVISION))
                {
                    log.Error("Error initializing security descriptor. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // get DACL from the security descriptor
                if (!NativeWrapper.GetSecurityDescriptorDacl(pSd, out daclPresent, ref pAcl, out daclExists))
                {
                    log.Error("Error requsting DACL from security descriptor. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }

                pAclSizeInfo = NativeWrapper.HeapAlloc(
                    NativeWrapper.GetProcessHeap(),
                    NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                    Convert.ToUInt32(Marshal.SizeOf(typeof(NativeWrapper.ACL_SIZE_INFORMATION))));

                // call only if DACL is not null
                if (pAcl != IntPtr.Zero)
                    if (!NativeWrapper.GetAclInformation(
                        pAcl,
                        pAclSizeInfo,
                        Convert.ToUInt32(Marshal.SizeOf(typeof(NativeWrapper.ACL_SIZE_INFORMATION))),
                        NativeWrapper.AclInformationClass.AclSizeInformation))
                    {
                        log.Error("Error retrieving ACL informations. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return false;
                    }

                // get managed object from pointer
                aclSizeInfo = (NativeWrapper.ACL_SIZE_INFORMATION)Marshal.PtrToStructure(pAclSizeInfo, typeof(NativeWrapper.ACL_SIZE_INFORMATION));

                // compute new DACL length
                newAclLength = aclSizeInfo.AclBytesInUse +
                    Convert.ToUInt32(Marshal.SizeOf(typeof(NativeWrapper.ACCESS_ALLOWED_ACE))) +
                    sidLength -
                    sizeof(uint);

                // allocate memory for new DACL
                pNewAcl = NativeWrapper.HeapAlloc(
                    NativeWrapper.GetProcessHeap(),
                    NativeWrapper.HeapAllocFlags.HEAP_ZERO_MEMORY,
                    newAclLength);
                if (pNewAcl == IntPtr.Zero)
                {
                    log.Error("Allocation of heap memory failed for new security descriptor buffer. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }

                // initialize new DACL
                if (!NativeWrapper.InitializeAcl(pNewAcl, newAclLength, NativeWrapper.ACL_REVISION))
                {
                    log.Error("Initialize ACL failed. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }

                // if DACL present copy it to a new DACL
                if (daclPresent)
                    for (uint i = 0; i < aclSizeInfo.AceCount; i++)
                    {
                        // get the ACE
                        if (!NativeWrapper.GetAce(pAcl, i, ref pTempAce))
                        {
                            log.Error("Error while getting ACE. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }

                        NativeWrapper.ACE_HEADER h = (NativeWrapper.ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(NativeWrapper.ACE_HEADER));


                        // add the ACE to the new ACL
                        if (!NativeWrapper.AddAce(
                            pNewAcl,
                            NativeWrapper.ACL_REVISION,
                            NativeWrapper.MAXDWORD,
                            pTempAce,
                            ((NativeWrapper.ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(NativeWrapper.ACE_HEADER))).AceSize))
                        {
                            log.Error("Error appending ACE to the new ACL. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            return false;
                        }
                    }
               

                if (!NativeWrapper.AddAccessAllowedAce(
                    pNewAcl,
                    NativeWrapper.ACL_REVISION,
                    NativeWrapper.AceAccessMask.DESKTOP_ALL,
                    pSid))
                {
                    log.Error("Error adding second ACE to new ACL for Window station Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
                // now set the new ACL for the new security descriptor
                if (!NativeWrapper.SetSecurityDescriptorDacl(pSdNew, true, pNewAcl, false))
                {
                    log.Error("Error setting new security descriptor ACL for window station.");
                    return false;
                }
                if (!NativeWrapper.SetUserObjectSecurity(hDesktop, ref si, pSdNew))
                {
                    log.Error("Error setting user object security to new security descriptor for window station. Win32 error [{0}].", new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return false;
                }
            }
            catch (Exception ex)
            {
                log.Error("Unhandled error while adding SID to window station. Exception [{0}].", ex.Message);
                return false;
            }
            finally
            {
				// this seems to throw an error
                //if (pTempAce != IntPtr.Zero)
                //    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pTempAce);
                if (pAclSizeInfo != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pAclSizeInfo);
                if (pNewAcl != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pNewAcl);
                if (pSd != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pSd);
                if (pSdNew != IntPtr.Zero)
                    NativeWrapper.HeapFree(NativeWrapper.GetProcessHeap(), 0, pSdNew);
            }
            return true;
        }

		/// <summary>
		/// Writes the given parameters to the HKLM/SOftware/Lukster/RunAsUser registry key
		/// </summary>
		/// <param name="commandLine"></param>
		/// <param name="exitCode"></param>
		private void WriteExitCode(string commandLine, int exitCode)
		{
			RegistryKey hklm = null;
			RegistryKey executionResultKey = null;
			try
			{
				hklm = Registry.LocalMachine;
				executionResultKey = hklm.CreateSubKey(@"SOFTWARE\Lukster\RunAsUser");
				// write values
				executionResultKey.SetValue("lastExecutedCmdLine", commandLine);
				executionResultKey.SetValue("lastExecutedExitcode", exitCode);
				executionResultKey.Flush();
			}
			catch (Exception ex)
			{
				log.Warn("Fatal error during write results to registry. Message: {0}", ex.Message);
			}
			finally
			{
				if (executionResultKey != null)
					executionResultKey.Close();
				if (hklm != null)
					hklm.Close();
			}
		}

		/// <summary>
		/// Waits the specified timeout for the process that is identified by the given handle 
		/// to exit. If the timeout is exceeded the execution of this thread will continue 
		/// wihtout the process to be terminated.
		/// </summary>
		/// <param name="hProcess">OS handle to the process</param>
		/// <param name="timeout">Timeout in milliseconds</param>
		/// <returns>true, if the process (has) exited within time.</returns>
		private bool WaitOne(IntPtr hProcess, uint timeout)
		{
			int waitForSingleObjectResult = NativeWrapper.WaitForSingleObject(hProcess, timeout);
			if (waitForSingleObjectResult == NativeWrapper.WAIT_OBJECT_0)
				log.Debug("Process exited gracefully. [Handle:{0}]", hProcess);
			else if (waitForSingleObjectResult == NativeWrapper.WAIT_TIMEOUT)
				log.Warn("Process timed out. [Handle:{0}] [Timeout:{1}ms]", hProcess, timeout);
			else if (waitForSingleObjectResult == NativeWrapper.WAIT_ABANDONED)
				log.Warn("Process already exited. [Handle:{0}]", hProcess);
			return waitForSingleObjectResult == NativeWrapper.WAIT_OBJECT_0 || waitForSingleObjectResult == NativeWrapper.WAIT_ABANDONED;
		}

		/// <summary>
		/// Gets the executable part 
		/// </summary>
		/// <param name="cmdLine"></param>
		/// <returns></returns>
		private string GetExecutable(string cmdLine)
		{
			if (string.IsNullOrEmpty(cmdLine))
				throw new ArgumentNullException("cmdLine");
			if (!cmdLine.Contains(" "))
				return cmdLine;

			return cmdLine.Substring(0, cmdLine.IndexOf(' '));
		}

		/// <summary>
		/// Gets the argument list that is after the executable
		/// </summary>
		/// <param name="cmdLine"></param>
		/// <returns></returns>
		private string GetArguments(string cmdLine)
		{
			if (string.IsNullOrEmpty(cmdLine))
				throw new ArgumentNullException("cmdLine");
			if (!cmdLine.Contains(" "))
				return string.Empty;

			return cmdLine.Substring(cmdLine.IndexOf(' ') + 1);
		}

		#region IDisposable Member
		/// <summary>
		/// Disposes all unmanaged resources
		/// </summary>
		public void Dispose()
		{
			if (closeAccessToken && hAccessToken != IntPtr.Zero)
				NativeWrapper.CloseHandle(hAccessToken);
		}

		#endregion
		#endregion
	}
}
