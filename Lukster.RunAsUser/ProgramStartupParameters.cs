using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Lukster.RunAsUser.Helper;
using Lukster.RunAsUser.Logging;

namespace Lukster.RunAsUser
{
	/// <summary>
	/// Enum that indicates how to retrieve the user access token.
	/// </summary>
	public enum ProcessCredentialMode
	{
		LoggedOnUser = 0,
		Username,
		CurrentProcessUser,
	}

	/// <summary>
	/// EWnum that indivates what should be done with the process when a timeout is reached.
	/// </summary>
	public enum ProcessTimeoutAction
	{
		Noop = 0,
		Kill
	}

	/// <summary>
	/// This class is used to parse the program arguments and make them
	/// more accessible for further use.
	/// </summary>
	internal sealed class ProgramStartupParameters
	{
		// default process name if no other is given
		public static readonly string DEFAULT_ACCESS_TOKEN_PROCESS = "explorer";
		public static readonly uint DEFAULT_PROCESS_TIMEOUT = 0x1B7740; // 30 minutes
		// member variables
		private string userName;
		private string userPassword;
		private string userDomain;
		private string accessTokenProcessName;
        private string accessTokenUserName;
		private string workingDirectory;
		private string logFile;
		private string cmdLine;
		private bool logToEventlogger;
		private bool logToFile;
		private bool logToConsole;
		private LogLevel logLevel;
		private bool loadUserProfile;
		private bool ignoreNoUser;
		private bool noInteractiveLogon;
		private uint timeout;
		private ProcessCredentialMode credentialMode;
		private ProcessTimeoutAction timeoutAction;

		/// <summary>
		/// parses all parameters and sets the appropriate properties
		/// </summary>
		/// <param name="arguments"></param>
		public ProgramStartupParameters(string[] arguments)
		{
			// first set defaults
			credentialMode = ProcessCredentialMode.LoggedOnUser;
			timeoutAction = ProcessTimeoutAction.Noop;
			logLevel = LogLevel.Fatal;

			// parse array
			for (int i = 0; i < arguments.Length; i++)
			{
				string lowerArg = arguments[i].ToLowerInvariant();

				if (lowerArg == CommandSwitches.LOG_TO_FILE)
				{
					if (i + 1 > arguments.Length) // <-- means this was the last parameter
						Program.ExitInvalidParams("Log to file switch is last parameter but there is no filename specified.");
					logToFile = true;
					logFile = arguments[++i];
				}
				else if (lowerArg == CommandSwitches.LOG_TO_CONSOLE)
					logToConsole = true;
				else if (lowerArg == CommandSwitches.LOG_TO_EVENTLOG)
					logToEventlogger = true;
				else if (lowerArg == CommandSwitches.LOG_LEVEL)
				{
					if (i + 1 > arguments.Length)
						Program.ExitInvalidParams("Log level switch is last but there is no level specified.");
					string lowerNext = arguments[++i].ToLowerInvariant();

					switch (lowerNext)
					{
						case "off":
						case "none":
							logLevel = LogLevel.None;
							break;
						case "debug":
							logLevel = LogLevel.Debug;
							break;
						case "info":
							logLevel = LogLevel.Info;
							break;
						case "warn":
							logLevel = LogLevel.Warn;
							break;
						case "error":
							logLevel = LogLevel.Error;
							break;
						case "fatal":
							logLevel = LogLevel.Fatal;
							break;
						case "all":
							logLevel = LogLevel.All;
							break;
						default:
							Program.ExitInvalidParams(string.Format("Unknown log level [{0}].", arguments[i]));
							break;
					}
				}
				else if (lowerArg == CommandSwitches.LOAD_USER_PROFILE)
					loadUserProfile = true;
				else if (lowerArg == CommandSwitches.NO_INTERACTIVE)
					noInteractiveLogon = true;
				else if (lowerArg == CommandSwitches.IGNORE_NO_USER)
					ignoreNoUser = true;
				else if (lowerArg == CommandSwitches.USERNAME)
				{
					if (i + 1 > arguments.Length)
						Program.ExitInvalidParams("Username switch was the last parameter, but there was no username specified.");

					string nextArg = arguments[++i];
					userDomain = IdentityHelper.GetIdentityPart(nextArg, IdentityPart.Domainname);
					userName = IdentityHelper.GetIdentityPart(nextArg, IdentityPart.Username);
					// this overrides all settings
					credentialMode = ProcessCredentialMode.Username;
				}
				else if (lowerArg == CommandSwitches.PASSWORD)
				{
					if (i + 1 > arguments.Length)
						Program.ExitInvalidParams("Password switch was the last parameter, but there was no password specified.");
					userPassword = arguments[++i];
				}
				else if (lowerArg == CommandSwitches.ACCESS_TOKEN_PROCESS)
				{
					if (i + 1 > arguments.Length)
						Program.ExitInvalidParams("Access token process switch was the last parameter, but there was no process name specified.");
					accessTokenProcessName = arguments[++i];
				}
                else if (lowerArg == CommandSwitches.ACCESS_TOKEN_ACCOUNT)
                {
                    if (i + 1 > arguments.Length)
                        Program.ExitInvalidParams("Access token process account name switch was the last parameter, but there was no user name specified.");
                    accessTokenUserName = arguments[++i];
                }
				else if (lowerArg == CommandSwitches.WORKING_DIRECTORY)
				{
					if (i + 1 > arguments.Length)
						Program.ExitInvalidParams("Working directory switch was the last parameter, but there was no directory specified.");
					workingDirectory = arguments[++i];
				}
				else if (lowerArg == CommandSwitches.PROCESS_TIMEOUT)
				{
					uint castedValue = 0;
					if (i + 1 > arguments.Length || !UInt32.TryParse(arguments[++i], out castedValue))
						Program.ExitInvalidParams("Process timeout switch found but no time interval was specified.");
					timeout = castedValue;
				}
				else if (lowerArg == CommandSwitches.PROCESS_TIMEOUT_ACTION)
				{
					if (i + 1 > arguments.Length)
						Program.ExitInvalidParams("Process timeout action was the last parameter, but there was no action specified.");

					string lowerNext = arguments[++i].ToLowerInvariant();
					switch (lowerNext)
					{
						case "kill":
							timeoutAction = ProcessTimeoutAction.Kill;
							break;
						case "noop":
							timeoutAction = ProcessTimeoutAction.Noop;
							break;
						default:
							Program.ExitInvalidParams(string.Format("Unknown timeout action found [{0}].", arguments[i]));
							break;
					}
				}
			}

			// now check if the parameters are correct in their dependencies
			if (logToFile && string.IsNullOrEmpty(logFile)) 
				Program.ExitInvalidParams("File logging is enabled but there is no file name specified.");
			if (!string.IsNullOrEmpty(workingDirectory) && !Directory.Exists(workingDirectory))
				Program.ExitInvalidParams("Specified working directory does not exist.");
			
			// last set the cmdline.. must be the last parameter
			cmdLine = arguments[arguments.Length - 1];
			
			if (string.IsNullOrEmpty(cmdLine))
				Program.ExitInvalidParams("No command line to execute.");
			if (cmdLine.StartsWith("/"))
				Program.ExitInvalidParams("Last parameter seem to be a program switch. The last parameter MUST be the command line that is to be executed.");
		}

		/// <summary>
		/// Gets the username
		/// </summary>
		public string Username
		{
			get
			{
				return userName;
			}
		}

		/// <summary>
		/// Gets the userdomain
		/// </summary>
		public string Userdomain
		{
			get
			{
				return userDomain;
			}
		}

		/// <summary>
		/// Gets the user password
		/// </summary>
		public string UserPassword
		{
			get
			{
				return userPassword;
			}
		}

		/// <summary>
		/// Gets the process timeout
		/// </summary>
		public uint ProcessTimeout
		{
			get
			{
				if (timeout == 0)
					return DEFAULT_PROCESS_TIMEOUT;
				else
					return timeout;
			}
		}

		/// <summary>
		/// Gets the timeout action that should be triggered when the process times out.
		/// </summary>
		public ProcessTimeoutAction ProcessTimeoutAction
		{
			get
			{
				return timeoutAction;
			}
		}

		/// <summary>
		/// Gets the user credentials mode
		/// </summary>
		public ProcessCredentialMode CredentialMode
		{
			get
			{
				return credentialMode;
			}
		}

		/// <summary>
		/// Gets the process name whose primary access token should be used
		/// </summary>
		public string AccessTokenProcessName
		{
			get
			{
				if (string.IsNullOrEmpty(accessTokenProcessName))
					return DEFAULT_ACCESS_TOKEN_PROCESS;
				else
					return accessTokenProcessName;
			}
		}

        public string AccessTokenAccountName
        {
            get
            {
                return accessTokenUserName;
            }
        }

		/// <summary>
		/// Gets the working directory that should be used
		/// </summary>
		public string WorkingDirectory
		{
			get
			{
				if (string.IsNullOrEmpty(workingDirectory))
					return Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
				else
					return workingDirectory;
			}
		}

		/// <summary>
		/// Gets the log level
		/// </summary>
		public LogLevel LogLevel
		{
			get
			{
				return logLevel;
			}
		}

		/// <summary>
		/// Gets the full log file name
		/// </summary>
		public string LogFileName
		{
			get
			{
				return logFile;
			}
		}

		/// <summary>
		/// Indicates that cosole logging should be enabled
		/// </summary>
		public bool ConsoleLoggingEnabled
		{
			get
			{
				return logToConsole;
			}
		}

		/// <summary>
		/// Indicates that file logging should be enabled
		/// </summary>
		public bool FileLoggingEnabled
		{
			get
			{
				return logToFile;
			}
		}

		/// <summary>
		/// Indicates that event logging should be enabled
		/// </summary>
		public bool EventLoggingEnabled
		{
			get
			{
				return logToEventlogger;
			}
		}

		/// <summary>
		/// Indicates that the user profile should be loaded prior to process execution.
		/// </summary>
		public bool LoadUserProfile
		{
			get
			{
				return loadUserProfile;
			}
		}

		/// <summary>
		/// Indicates that the process execution should NOT be interactive wiht the current desktop
		/// </summary>
		public bool NoInteractiveLogon
		{
			get
			{
				return noInteractiveLogon;
			}
		}

		/// <summary>
		/// Indicates that no error should be thrown when no access token could be retrieved.
		/// </summary>
		public bool IgnoreNoUser
		{
			get
			{
				return ignoreNoUser;
			}
		}

		/// <summary>
		/// Gets the command line that should be executed.
		/// </summary>
		public string Commandline
		{
			get
			{
				return cmdLine;
			}
		}
	}
}
