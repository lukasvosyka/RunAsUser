using System;
using System.Collections.Generic;
using System.Text;

namespace Lukster.RunAsUser
{
	/// <summary>
	/// This includes all exit codes returned by this application.
	/// </summary>
	internal sealed class ExitCodes
	{
		// general error codes
		/// <summary>
		/// Indicates that no error occured.
		/// </summary>
		public const int OK = 0;
		/// <summary>
		/// Indicates that no parameters where given.
		/// </summary>
		public const int NO_PARAMETERS = 1;
		/// <summary>
		/// Indicates that the parameter list was errornous. There can be different reasons. Missing parameters or wrong entered parameters. 
		/// Remember that the last parameter MUST be the command line entered in quotas.
		/// </summary>
		public const int INVALID_PARAMETERS = 2;
		/// <summary>
		/// Indicates that a terminal server session was detected. This tool cannot run in terminal session.
		/// </summary>
		public const int TERMINAL_SERVER_DETECTED = 3;
		/// <summary>
		/// This is a general error that occured somehow. Please check the logs for further details.
		/// </summary>
		public const int ERROR_WHILE_EXECUTION = 4;
		/// <summary>
		/// While starting the process some error occured. Please check the logs for further details.
		/// </summary>
		public const int PROCESS_START_ERROR = 5;
        /// <summary>
        /// If the current user principal cannot be retrieved, so we don't know who has started the process
        /// we cannot continue.
        /// </summary>
        public const int ERROR_RETRIEVING_CURRENT_USER = 6;
		// log file creation error codes
		/// <summary>
		/// Indicates that the access to the provided log file was denied by the OS.
		/// Please check the file security for the user that is running this tool.
		/// </summary>
		public const int LOG_FILE_ACCESS_DENIED = 10;
		/// <summary>
		/// Indicates that some error occured while creating the log file. Please check the
		/// console log to get further information.
		/// </summary>
		public const int LOG_FILE_CREATE_ERROR = 11;
		/// <summary>
		/// Indicates that the access to the event log was denied by the OS.
		/// Please check the event log security settings for the user running this tool.
		/// </summary>
		public const int LOG_EVENTLOG_ACCESS_DENIED = 12;
		/// <summary>
		/// Indicates that the creation of the event log source was denied. 
		/// Please check the event log security settings for the user running this tool.
		/// </summary>
		public const int LOG_EVENTLOG_CREATE_ERROR = 13;
		// errors while user security context creation
		/// <summary>
		/// Indicates that no access token could be retrieved to start a process under certain user credentials.
		/// </summary>
		public const int NO_ACCESS_TOKEN_PROCESS_RUNNING = 20;
		/// <summary>
		/// Indicates that access to open the access token of a process was denied.
		/// Please check the process priviledges for the user running this tool, granted the proviledges: QUERY_PROCESS_INFORMATION
		/// </summary>
		public const int OPEN_ACCESS_TOKEN_ACCESS_DENIED = 21;
		/// <summary>
		/// Indicates that the creation of the process that is to be started failed. This can have many reasons. Please check the
		/// logs for further details and take a look for the Win32 error code that was returned by the CreateProcessAsUser win32 API call.
		/// Another possible error is that the priviledges for the process are not held. SE_TCB_NAME and SE_ASSIGNPRIMARYTOKEN_NAME are required.
		/// </summary>
		public const int CREATE_PROCESS_ERROR = 22;
		/// <summary>
		/// Indicates that a strange error has happend. The process handle got lost and the process might be in a running state.
		/// This should not happen anyway.
		/// </summary>
		public const int CREATE_PROCESS_NO_PROCESS_HANDLE = 23;
		/// <summary>
		/// Indicates that a process that has been started exceeded the given timeout.
		/// </summary>
		public const int CREATE_PROCESS_FINISH_TIMED_OUT = 24;
		/// <summary>
		/// Indicates that the user logon with username and password has failed.
		/// Pleasee check the logs for further details.
		/// </summary>
		public const int LOGON_USER_FAILED = 25;
		/// <summary>
		/// Indicates that loading the user profile failed. 
		/// Please check the logs for further details.
		/// </summary>
		public const int LOAD_USER_PROFILE_FAILED = 26;
        /// <summary>
        /// Indicates that no handle to the window station could be obtained.
        /// </summary>
        public const int GET_WINDOW_STATION_FAILED = 27;
        /// <summary>
        /// Indicates that setting the window station failed.
        /// </summary>
        public const int SET_WINDOW_STATION_FAILED = 28;
        /// <summary>
        /// Indicates that no handle to the desktop could be obtained.
        /// </summary>
        public const int OPEN_DESKTOP_FAILED = 29;
        /// <summary>
        /// Indicates that the SID could not be retrieved.
        /// </summary>
        public const int GET_SECURITY_ID_FAILED = 30;
        /// <summary>
        /// Indicates that an error occured while adding new ACEs to the windows station.
        /// </summary>
        public const int ADD_ACE_TO_WINDOW_STATION_FAILED = 31;
        /// <summary>
        /// Indicates that an error occured while adding new ACE to the desktop.
        /// </summary>
        public const int ADD_ACE_TO_DESKTOP_FAILED = 32;
	}
}
