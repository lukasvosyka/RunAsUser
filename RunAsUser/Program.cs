using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;
using RunAsUser.Logging;
using System.Security;
using System.IO;
using RunAsUser.IO;
using RunAsUser.Helper;
using System.ComponentModel;

namespace RunAsUser
{
    /// <summary>
    /// Entry class
    /// </summary>
	public class Program
	{
		private static Logger log = LogFactory.GetLogger(typeof(Program));

		public static void Main(string[] args)
		{
			// process start object
			ProcessStart ps = null;

			try
			{
				// if no parameters or help was provided
				if (args.Length == 0 ||
					Array.Exists<string>(args, delegate(string s)
				{
					return s.ToLowerInvariant() == CommandSwitches.HELP;
				}))
				{
					ShowUsageInfo();
					Environment.Exit(args.Length == 1 ? ExitCodes.OK : ExitCodes.NO_PARAMETERS);
				}
				// get prepared startup parameters
				ProgramStartupParameters param = new ProgramStartupParameters(args);
				// ensure correct logging targets as given per arguments
				// do this before all other stuff, so we can ensure that these loggings are
				// activated if errors occur.
				LogFactory.InitConfiguration(param);
				// without knowledge of the current user, we exit here
                WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                if (currentUser == null)
                {
                    log.Fatal("Could not retrieve current user information.");
                    Program.Exit(ExitCodes.ERROR_RETRIEVING_CURRENT_USER);
                }
				log.Info("RunAsUser started execution by [{0}] on {1} with arguments [{2}]", currentUser.Name, DateTime.Now.ToString("G"), string.Join(" ", args));
				// if terminal server detected
				// TODO: check if impersonation influences this behavior
				if (RunningOnTerminalServer)
				{
					log.Fatal("This tool cannot be run under Terminal Server environment!");
					Program.Exit(ExitCodes.TERMINAL_SERVER_DETECTED);
				}
				// create and initialize processstart object
				// check if user credential informations are given per username and password
				if (param.CredentialMode == ProcessCredentialMode.Username)
				{
					log.Info("Username and Password have been provided for creating primary access token. Username:[{0}]", string.IsNullOrEmpty(param.Userdomain) ? param.Username : string.Format("{0}\\{1}", param.Userdomain, param.Username));
					ps = new ProcessStart(param.Username, param.UserPassword, param.Userdomain);
				}
				else if (param.CredentialMode == ProcessCredentialMode.LoggedOnUser)
				{
					string usedProcessName = param.AccessTokenProcessName.Trim();
					if (usedProcessName[usedProcessName.Length - 4] == '.')
						usedProcessName = usedProcessName.Substring(0, usedProcessName.Length - 4);

					log.Info("Process will be started using primary access token of first process found called [{0}].", usedProcessName);
					// find all processes
					Process[] accessTokenProcesses = Process.GetProcessesByName(usedProcessName);
					// if nothing found..error
					if (accessTokenProcesses.Length == 0)
					{
						log.Fatal("No process called [{0}] could be found resulting that no primary access token can be used.", param.AccessTokenProcessName);
						if (param.IgnoreNoUser)
						{
							log.Info("Conigured to exit OK although no user could be retrieved to execute process.");
							Program.Exit(ExitCodes.OK);
						}
						else
							Program.Exit(ExitCodes.OPEN_ACCESS_TOKEN_ACCESS_DENIED);
					}

					// With logged on user is meant, a user that has been logged on using winlogon.exe. 
					// Per default a process called "explorer"
					// is used to retrieve the primary access token for the user that is to be used.
					// Therefor the process that is running this code must have priviledges granted to PROCESS_QUERY_INFORMATION

                    // TODO: The current processes' privileges must be enusred to have SE_DEBUG_NAME and SE_TCB_NAME enabled.
                    // To do so following steps must be done:
                    // OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES)
                    // LookupPrivilegeValue("SeDebugPrivilege")
                    // AdjustTokenPrivilege()
                    EnsureCurrentProcessDebugPrivilegeEnabled();
                    
					IntPtr tokenHandle = IntPtr.Zero;
                    Process p = null;
                    if (!string.IsNullOrEmpty(param.AccessTokenAccountName))
                    {
                        foreach (Process t in accessTokenProcesses)
                        {
                            bool result = NativeWrapper.OpenProcessToken(
                            t.Handle,
                            NativeWrapper.TOKEN_QUERY | NativeWrapper.TOKEN_DUPLICATE | NativeWrapper.TOKEN_ASSIGN_PRIMARY,
                            out tokenHandle);
                            if (!result)
                            {
                                log.Fatal("Error opening process token for process [PID:{0} Name:{1}]. Win32 error: {2}", p.Id, p.ProcessName, new Win32Exception(Marshal.GetLastWin32Error()).Message);
                                if (param.IgnoreNoUser)
                                {
                                    log.Info("Configured to exit OK although no user could be retrieved to execute process.");
                                    Program.Exit(ExitCodes.OK);
                                }
                                else
                                    Program.Exit(ExitCodes.OPEN_ACCESS_TOKEN_ACCESS_DENIED);
                            }
                            else
                            {
                                WindowsIdentity id = new WindowsIdentity(tokenHandle);
                                if (string.Equals(id.Name, param.AccessTokenAccountName, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    p = t;
                                    break;
                                }
                            }
                        }
                        if (p == null)
                        {
                            log.Fatal("No process called [{0}] could be found under account name [{1}].", param.AccessTokenProcessName, param.AccessTokenAccountName);
                            Program.Exit(ExitCodes.NO_ACCESS_TOKEN_PROCESS_RUNNING);
                        }
                    }
                    else
                    {
                        p = accessTokenProcesses[0];
                        
                        bool result = NativeWrapper.OpenProcessToken(
                            p.Handle,
                            NativeWrapper.TOKEN_QUERY | NativeWrapper.TOKEN_DUPLICATE | NativeWrapper.TOKEN_ASSIGN_PRIMARY,
                            out tokenHandle);
                        if (!result)
                        {
                            log.Fatal("Error opening process token for process [PID:{0} Name:{1}]. Win32 error: {2}", p.Id, p.ProcessName, new Win32Exception(Marshal.GetLastWin32Error()).Message);
                            if (param.IgnoreNoUser)
                            {
                                log.Info("Configured to exit OK although no user could be retrieved to execute process.");
                                Program.Exit(ExitCodes.OK);
                            }
                            else
                                Program.Exit(ExitCodes.OPEN_ACCESS_TOKEN_ACCESS_DENIED);
                        }
                    }

					ps = new ProcessStart(tokenHandle, true);
				}
				ps.CreateNoWindow = true;
				ps.ProcessTimeout = param.ProcessTimeout;
				ps.ProcessTimeoutAction = param.ProcessTimeoutAction;
				ps.Interactive = !param.NoInteractiveLogon;
				ps.LoadUserProfile = param.LoadUserProfile;
				ps.WorkingDirectory = param.WorkingDirectory;
				// start
				int processStartResult = ps.Start(param.Commandline);

				Program.Exit(processStartResult);
			}
			catch (Exception ex)
			{
				log.Fatal("Error while execution. Message: {0}", ex.Message);
				Program.Exit(ExitCodes.ERROR_WHILE_EXECUTION);
			}
			finally
			{
				if (ps != null)
					ps.Dispose();
			}
		}

        private static void EnsureCurrentProcessDebugPrivilegeEnabled()
        {
            IntPtr hToken = IntPtr.Zero;
            NativeWrapper.LUID newLuid = new NativeWrapper.LUID();
            NativeWrapper.TOKEN_PRIVILEGES newPrivilege = new NativeWrapper.TOKEN_PRIVILEGES();

            try
            {
                bool result = NativeWrapper.OpenProcessToken(Process.GetCurrentProcess().Handle, NativeWrapper.TOKEN_ADJUST_PRIVILEGES, out hToken);
                if (!result)
                {
                    log.Fatal("Error ensuring currents' process access rights");
                    Program.Exit(ExitCodes.ERROR_WHILE_EXECUTION);
                }

                result = NativeWrapper.LookupPrivilegeValue(null, NativeWrapper.SE_DEBUG_NAME, out newLuid);
                if (!result)
                {
                    log.Fatal("Unable to determine LUID");
                    Program.Exit(ExitCodes.ERROR_WHILE_EXECUTION);
                }

                newPrivilege.PrivilegeCount = 1;
                newPrivilege.Luid = newLuid;
                newPrivilege.Attributes = NativeWrapper.SE_PRIVILEGE_ENABLED;

                result = NativeWrapper.AdjustTokenPrivileges(
                    hToken,
                    false,
                    ref newPrivilege,
                    0,
                    IntPtr.Zero,
                    0);
                if (!result)
                {
                    log.Fatal("Error adjusting process privileges");
                    Program.Exit(ExitCodes.ERROR_WHILE_EXECUTION);
                }

                result = NativeWrapper.LookupPrivilegeValue(null, NativeWrapper.SE_TCB_NAME, out newLuid);
                if (!result)
                {
                    log.Fatal("Unable to determine LUID");
                    Program.Exit(ExitCodes.ERROR_WHILE_EXECUTION);
                }

                newPrivilege.PrivilegeCount = 1;
                newPrivilege.Luid = newLuid;
                newPrivilege.Attributes = NativeWrapper.SE_PRIVILEGE_ENABLED;

                result = NativeWrapper.AdjustTokenPrivileges(
                    hToken,
                    false,
                    ref newPrivilege,
                    0,
                    IntPtr.Zero,
                    0);
                if (!result)
                {
                    log.Fatal("Error adjusting process privileges");
                    Program.Exit(ExitCodes.ERROR_WHILE_EXECUTION);
                }
            }
            catch (Exception ex)
            {
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                    NativeWrapper.CloseHandle(hToken);
            }
        }

		/// <summary>
		/// Shows the help message on the console.
		/// </summary>
		private static void ShowUsageInfo()
		{
			Console.WriteLine();
			Console.WriteLine("RunAsUser Command Tool - .Net v{0}", Environment.Version.ToString());
			Console.WriteLine(".........................................................");
			Console.WriteLine();
			Console.WriteLine("Usage:");
			Console.WriteLine("-----------");
			Console.WriteLine("{0} [Options] [Command]", Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().MainModule.FileName));
			Console.WriteLine();
			Console.WriteLine("Options:");
			Console.WriteLine("-----------");
			Console.WriteLine("{0}\t\t\t[optional]", CommandSwitches.HELP);
			Console.WriteLine("\tDisplays this help message.");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.LOG_TO_CONSOLE);
			Console.WriteLine("\tLogs all messages to the console.");
			Console.WriteLine();
			Console.WriteLine("{0} Filename\t[optional]", CommandSwitches.LOG_TO_FILE);
			Console.WriteLine("\tLogs all messages to a given file.");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.LOG_TO_EVENTLOG);
			Console.WriteLine("\tLogs all messages to the event log.");
			Console.WriteLine();
			Console.WriteLine("{0} all\t\t[optional]", CommandSwitches.LOG_LEVEL);
			Console.WriteLine("\tSets the log level. Possible values are off|info|debug|warn|error|fatal. Default is Fatal");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.USERNAME);
			Console.WriteLine("\tSets the username that should be used for execution. Per default the logged on user is used.");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.PASSWORD);
			Console.WriteLine("\tSets the password for the user that is used with the username option.");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.IGNORE_NO_USER);
			Console.WriteLine("\tNo error will be raised, if no user could be obtained. Exit code will be OK, but the process did not start.");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.NO_INTERACTIVE);
			Console.WriteLine("\tDo NOT use desktop interaction while impersonation.");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.LOAD_USER_PROFILE);
			Console.WriteLine("\tLoads the user profile for the impersonated user. This switch is only used when username and password are provided.");
			Console.WriteLine();
			Console.WriteLine("{0}\t\t[optional]", CommandSwitches.WORKING_DIRECTORY);
			Console.WriteLine("\tSets the working directory for the executing process. Default is the directory where this tool resides.");
			Console.WriteLine();
            Console.WriteLine("{0}\t[optional]", CommandSwitches.ACCESS_TOKEN_PROCESS);
            Console.WriteLine("\tSets the process name that should be used to retrieve the primary access token that should be used with the process. Default is explorer.exe");
            Console.WriteLine();
            Console.WriteLine("{0}\t[optional]", CommandSwitches.ACCESS_TOKEN_ACCOUNT);
            Console.WriteLine("\tSets the process account name that should be used when there are than one process running under different credentials. Default is the first process found.");
            Console.WriteLine();
            Console.WriteLine("{0} 60000\t\t[optional]", CommandSwitches.PROCESS_TIMEOUT);
			Console.WriteLine("\tSets the time in milliseconds that should be waited until the process finishes gracefully. Default is 1800000 (0,5h)");
			Console.WriteLine();
			Console.WriteLine("{0} kill\t[optional]", CommandSwitches.PROCESS_TIMEOUT_ACTION);
			Console.WriteLine("\tSets the timeout action that should be done in case the process times out. Possible values are: noop|kill. Default is noop.");
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("Command:");
			Console.WriteLine("-----------");
			Console.WriteLine("\tEnter the commandline that is to be executed with all parameters.");
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("Example:");
			Console.WriteLine("-----------");
			Console.WriteLine("\t{0} {1} \"C:\\ra-log\\log.txt\" {2} {3} all \"cmd /c pause\"", Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().MainModule.FileName), CommandSwitches.LOG_TO_FILE, CommandSwitches.LOG_TO_EVENTLOG, CommandSwitches.LOG_LEVEL);
			Console.WriteLine(".........................................................");
			Console.WriteLine();
		}

		/// <summary>
		/// Returns true, if the tool is executed on a terminal services session.
		/// </summary>
		public static bool RunningOnTerminalServer
		{
			get
			{
				return ((NativeWrapper.GetSystemMetrics(0x1000) & 1) != 0);
			}
		}

		/// <summary>
		/// Logs the exit code and exits the process with the given exit code.
		/// </summary>
		/// <param name="exitCode"></param>
		internal static void Exit(int exitCode)
		{
			ExitWithMessage(exitCode, null);
		}

		/// <summary>
		/// Exits the process and returns the exit code. If a message is given, it will be sent to the
		/// attached output console. In case the exit code is INVALID_PARAMETERS the help message is displayed as well.
		/// </summary>
		/// <param name="exitCode">exit code</param>
		/// <param name="message">message that should be displayed. If null or empty nothing will be displayed.</param>
		internal static void ExitWithMessage(int exitCode, string message)
		{
			log.Info("Program exits with Exitcode:\t{0}", exitCode);
			
			if (exitCode == ExitCodes.INVALID_PARAMETERS)
				ShowUsageInfo();

			if(!string.IsNullOrEmpty(message))
				Console.WriteLine(message);

			Environment.Exit(exitCode);
		}

		/// <summary>
		/// Helper function for ProgramStartupParameters object
		/// </summary>
		/// <param name="message"></param>
		internal static void ExitInvalidParams(string message)
		{
			ExitWithMessage(ExitCodes.INVALID_PARAMETERS, string.Format("Invalid parameters: {0}", message));
		}

	}
}
