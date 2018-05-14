@echo off
setlocal

REM change directory
%~d0
cd %~p0

REM Java Setting
set JCP_OPT=-classpath .;../lib/freexades-0.2.jar

echo Sample Compile.
javac %JCP_OPT% FxSample.java

echo Sample Execute.
java %JCP_OPT% FxSample

echo Sample Finished.
endlocal
