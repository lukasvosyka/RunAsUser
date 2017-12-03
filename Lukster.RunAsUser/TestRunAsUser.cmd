@echo off
:: This is a test script for the RunAsUser tool.
:: This will try to run some commands as a user using different combinations
:: of command line switches.
:: To test this under different process user credentials use cron jobs
:: Put into cmd line:
:: schtasks /create /ru SYSTEM /st <start-time> /sc ONCE /tn "Test-RunAs" /tr TestRunAsUser.cmd

:: define some variables
set RUNAS=.\bin\debug\ra.exe
set LOGFILE=ra-test.log
set NOTEPAD=%windir%\notepad.exe

:: define command switches
set LOG_TO_CONSOLE=/logconsole
set LOG_TO_FILE=/logfile
set LOG_TO_EVENTLOG=/logevent
set LOG_ALL=/level all
set USERNAME=/username
set PASSWORD=/password
set IGNORE_USER=/ignoreuser
set NO_INTERACTIVE=/nointeractive
set WORKING_DIRECTORY=/workingdir
set LOAD_USER_PROFILE=/profile
set ACCESS_TOKEN_PROCESS=/accesstokenprocess
set PROCESS_TIMEOUT=/timeout
set PROCESS_TIMEOUT_ACTION=/timeoutaction
set TIMEOUT_ACTION_NOOP=noop
set TIMEOUT_ACTION_KILL=kill
set TIMEOUT=5000

:: test different cases
%RUNAS% %LOG_TO_FILE% %LOGFILE% %LOG_ALL% %PROCESS_TIMEOUT% %TIMEOUT% %PROCESS_TIMEOUT_ACTION% %TIMEOUT_ACTION_KILL% "%NOTEPAD% somefile.txt"