using System;
using System.Collections.Generic;
using System.Text;

namespace Lukster.RunAsUser
{
    /// <summary>
    /// Command parameter switches
    /// </summary>
	internal sealed class CommandSwitches
	{
		public const string HELP = "/h";
		public const string LOG_TO_CONSOLE = "/logconsole";
		public const string LOG_TO_FILE = "/logfile";
		public const string LOG_TO_EVENTLOG = "/logevent";
		public const string LOG_LEVEL = "/level";
		public const string USERNAME = "/username";
		public const string PASSWORD = "/password";
		public const string IGNORE_NO_USER = "/ignorenouser";
		public const string NO_INTERACTIVE = "/nointeractive";
		public const string WORKING_DIRECTORY = "/workingdir";
		public const string LOAD_USER_PROFILE = "/profile";
		public const string ACCESS_TOKEN_PROCESS = "/accesstokenprocess";
        public const string ACCESS_TOKEN_ACCOUNT = "/accesstokenaccount";
		public const string PROCESS_TIMEOUT = "/timeout";
		public const string PROCESS_TIMEOUT_ACTION = "/timeoutaction";
	}
}
