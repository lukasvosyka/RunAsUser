using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Security;

namespace RunAsUser.Logging
{
	[Flags]
	internal enum LogTarget
	{
		None = 0,
		Console = 1,
		File = 2,
		EventLog = 4,
	}

	internal enum LogType
	{
		Info = 0,
		Debug,
		Warn,
		Error,
		Fatal,
	}

	internal enum LogLevel
	{
		All = 0,
		Info,
		Debug,
		Warn,
		Error,
		Fatal,
		None
	}

	/// <summary>
	/// This log factory returns single instances of loggers for each source.
	/// </summary>
	internal static class LogFactory
	{
		// lock mutex
		private static readonly object lockMutex = new object();
		// registred loggers per type
		private static Dictionary<string, Logger> registeredLoggers;
		// parameters
		private static ProgramStartupParameters parameters = null;

		static LogFactory()
		{
			registeredLoggers = new Dictionary<string, Logger>();
		}

		/// <summary>
		/// Initializes all current loggers and all further loggers with the startup parameters.
		/// </summary>
		/// <param name="parameters"></param>
		public static void InitConfiguration(ProgramStartupParameters parameters)
		{
			if(LogFactory.parameters == null)
				lock (lockMutex)
					if (LogFactory.parameters == null)
					{
						LogFactory.parameters = parameters;
						if (registeredLoggers.Count > 0)
							foreach (Logger registeredLogger in registeredLoggers.Values)
								EnsureLoggerConfiguration(registeredLogger, parameters);
					}
		}

		/// <summary>
		/// Ensures log level, log target configuration
		/// </summary>
		/// <param name="log"></param>
		/// <param name="args"></param>
		private static void EnsureLoggerConfiguration(Logger log, ProgramStartupParameters psp)
		{
			if (log == null)
				throw new ArgumentNullException("log");
			if (psp == null)
				throw new ArgumentNullException("psp");

			if (psp.ConsoleLoggingEnabled)
			{
				log.EnableConsoleLogging();
			}
			if (psp.FileLoggingEnabled)
			{
				try
				{
					log.EnableFileLogging(psp.LogFileName);
				}
				catch (UnauthorizedAccessException)
				{
					Program.Exit(ExitCodes.LOG_FILE_ACCESS_DENIED);
				}
				catch (Exception)
				{
					Program.Exit(ExitCodes.LOG_FILE_CREATE_ERROR);
				}
			}
			if (psp.EventLoggingEnabled)
			{
				try
				{
					log.EnableEventLogLogging("RunAsUser");
				}
				catch (SecurityException)
				{
					Program.Exit(ExitCodes.LOG_EVENTLOG_ACCESS_DENIED);
				}
				catch (Exception)
				{
					Program.Exit(ExitCodes.LOG_EVENTLOG_CREATE_ERROR);
				}
			}

			log.Level = psp.LogLevel;
		}

		/// <summary>
		/// Returns a prop. newly created logger for the given type.
		/// </summary>
		/// <param name="sourceType"></param>
		/// <returns></returns>
		public static Logger GetLogger(Type sourceType)
		{
			return GetLogger(sourceType.Name);
		}

		/// <summary>
		/// Returns a prop. newly created logger for the given name
		/// </summary>
		/// <param name="source"></param>
		/// <returns></returns>
		public static Logger GetLogger(string source)
		{
			if (string.IsNullOrEmpty(source))
				throw new ArgumentNullException("source");
			if (!registeredLoggers.ContainsKey(source))
				lock (lockMutex)
					if (!registeredLoggers.ContainsKey(source))
					{
						Logger newLogger = new Logger(source);
						if (parameters != null)
							EnsureLoggerConfiguration(newLogger, parameters);
						registeredLoggers.Add(source, newLogger);
					}

			return registeredLoggers[source];
		}
	}

	/// <summary>
	/// This logger is a simple logging mechanism to log to diffent log targets, like file, console or event log.
	/// </summary>
	internal sealed class Logger
	{
		private string sourceName;
		private LogTarget logTarget;
		private string logFileName;
		private EventLog eventLogger;
		private LogLevel logLevel;

		public Logger(string source)
		{
			this.sourceName = source;
			logTarget = LogTarget.None;
			logLevel = LogLevel.Fatal;
		}

		/// <summary>
		/// Sets or gets the log level
		/// </summary>
		public LogLevel Level
		{
			get
			{
				return logLevel;
			}
			set
			{
				logLevel = value;
			}
		}

		public void EnableConsoleLogging()
		{
			logTarget |= LogTarget.Console;
		}

		public void EnableFileLogging(string fileName)
		{
			if (string.IsNullOrEmpty(fileName))
				throw new ArgumentNullException("fileName");

			string logDirectory = Path.GetDirectoryName(fileName);
			if (!string.IsNullOrEmpty(logDirectory) && !Directory.Exists(logDirectory))
				Directory.CreateDirectory(logDirectory);
			
			logFileName = fileName;
			logTarget |= LogTarget.File;
		}

		public void EnableEventLogLogging(string sourceName)
		{
			if (string.IsNullOrEmpty(sourceName))
				throw new ArgumentNullException("sourceName");
			// create source in event log if not existant
			if (!EventLog.SourceExists(sourceName))
				EventLog.CreateEventSource(sourceName, "Lukster RunAs");

			eventLogger = new EventLog();
			eventLogger.Source = sourceName;

			logTarget |= LogTarget.EventLog;
		}

		private void Log(string prepareMessage, LogType type)
		{
			if (!Enum.IsDefined(typeof(LogType), type))
				throw new ArgumentException("type");
			// add default informations
			prepareMessage = string.Format("[{0}]\t[{1}] - [{2}]\t{3}",
				type.ToString().ToUpperInvariant(),
				DateTime.Now.ToString("G"),
				sourceName,
				prepareMessage);
			// logging off
			if (logTarget == LogTarget.None)
				return;
			// logging on
			if ((logTarget & LogTarget.Console) == LogTarget.Console)
				Console.WriteLine(prepareMessage);
			if ((logTarget & LogTarget.File) == LogTarget.File)
				File.AppendAllText(logFileName, string.Format("{0}{1}", prepareMessage, Environment.NewLine));
			if ((logTarget & LogTarget.EventLog) == LogTarget.EventLog)
			{
				if (type == LogType.Info)
					eventLogger.WriteEntry(prepareMessage, EventLogEntryType.Information);
				else if (type == LogType.Debug)
					eventLogger.WriteEntry(prepareMessage, EventLogEntryType.Information);
				else if (type == LogType.Warn)
					eventLogger.WriteEntry(prepareMessage, EventLogEntryType.Warning);
				else if (type == LogType.Error || type == LogType.Fatal)
					eventLogger.WriteEntry(prepareMessage, EventLogEntryType.Error);
				else
					throw new ArgumentException("type");
			}
		}

		public void Info(string message)
		{
			if (logLevel <= LogLevel.Info)
				Log(message, LogType.Info);
		}

		public void Info(string message, params object[] param)
		{
			Info(string.Format(message, param));
		}

		public void Debug(string message)
		{
			if (logLevel <= LogLevel.Debug)
				Log(message, LogType.Debug);
		}

		public void Debug(string message, params object[] param)
		{
			Debug(string.Format(message, param));
		}

		public void Warn(string message)
		{
			if (logLevel <= LogLevel.Warn)
				Log(message, LogType.Warn);
		}

		public void Warn(string message, params object[] param)
		{
			Warn(string.Format(message, param));
		}

		public void Error(string message)
		{
			if (logLevel <= LogLevel.Error)
				Log(message, LogType.Error);
		}

		public void Error(string message, params object[] param)
		{
			Error(string.Format(message, param));
		}

		public void Fatal(string message)
		{
			if (logLevel <= LogLevel.Fatal)
				Log(message, LogType.Fatal);
		}

		public void Fatal(string message, params object[] param)
		{
			Fatal(string.Format(message, param));
		}
	}
}
