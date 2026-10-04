@echo off
rem pm launcher for the Windows release archive (docs/release/packaging.md). Layout:
rem   <home>\bin\pm.bat   this script
rem   <home>\runtime\     jlink runtime (JDK modules only; no JDWP, JMX or attach, SR-801)
rem   <home>\app\         pm and its dependency module jars, byte-identical to the SBOM hashes
rem JVM hardening flags are baked into the runtime by jlink --add-options (SR-502).
rem Environment-supplied JVM options are cleared so they cannot alter the command line (ENV05-J).
setlocal
set "JAVA_TOOL_OPTIONS="
set "JDK_JAVA_OPTIONS="
set "_JAVA_OPTIONS="
set "CLASSPATH="
set "PM_HOME=%~dp0.."
"%PM_HOME%\runtime\bin\java.exe" -p "%PM_HOME%\app" -m pm.cli/pm.cli.Main %*
exit /b %ERRORLEVEL%
