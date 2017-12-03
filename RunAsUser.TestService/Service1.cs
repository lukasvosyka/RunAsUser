using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.ServiceProcess;
using System.Text;

namespace RunAsUser.TestService
{
	public partial class Service1 : ServiceBase
	{
		public Service1()
		{
			InitializeComponent();
		}

		protected override void OnStart(string[] args)
		{
			//Debugger.Break();
			RunAsUser.Program.Main(new string[] { 
				//"/u",
				//"TestUser",
				//"/p",
				//"harley",
				"/logfile",
				"c:\\mylog.log",
				"/logevent",
				"/profile",
				"/level",
				"all",
				//"/d",
				//"c:\\",
				"C:\\Windows\\notepad.exe" });
		}

		protected override void OnStop()
		{
		}
	}
}
