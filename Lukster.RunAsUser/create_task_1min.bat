
REM get time to calc starting time
FOR  /F "tokens=1,2 delims=:" %%a in ('time /t') do (
    set HH=%%a
    set MM=%%b
)

REM add two minutes
set /a MM+=1
REM if lower than 10 add a '0' to the minutes at the beginning
IF (%MM%) LSS (10) (
    set MM=0%MM%
)
REM schedule the task
SCHTASKS /Create /RU System /SC ONCE /ST %HH%:%MM%:00 /TN TestRunAsUser_Batch /TR "%~dp0%TestRunAsUser.cmd"
REM inform user
echo Your task begins at %HH%:%MM% o'clock
pause