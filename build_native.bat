@echo off
setlocal

if "%JAVA_HOME%"=="" (
    echo JAVA_HOME is not set.
    exit /b 1
)

if not exist "%JAVA_HOME%\include" (
    echo JAVA_HOME\include not found.
    exit /b 1
)

if not exist "C:\OpenSSL-Win64\include" (
    echo OpenSSL include path not found. Please install OpenSSL and update this script.
    exit /b 1
)

cl /EHsc ^
  /I"%JAVA_HOME%\include" ^
  /I"%JAVA_HOME%\include\win32" ^
  /I"C:\OpenSSL-Win64\include" ^
  /LD src\native\com_seaboat_bytecode_ByteCodeEncryptor.cpp ^
  /link /OUT:ByteCodeEncryptor.dll ^
  /LIBPATH:"C:\OpenSSL-Win64\lib" libcrypto.lib

echo Build complete.
