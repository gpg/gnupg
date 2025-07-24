@echo on
rem Decrypt all files in the input to the output directory.
rem The input directory and the suffixes are defined by
rem constants given below.

rem Set the input/output directories and the suffixes.
set INDIR=c:\input-files
set OUTDIR=c:\output-files
set INSUFFIX=.gpg
set OUTSUFFIX=
set LOGFILE=%APPDATA%\decrypt.log

rem No serviceable parts below.

set GPGARGS=--batch --yes --log-file "%LOGFILE%" --require-compliance
cd %INDIR%
mkdir %OUTDIR% 2>nul
for /R %%f in (*%INSUFFIX%) do (
    setlocal enabledelayedexpansion
    for %%i in ("%%f") do (
        set filename=%%~ni
    )
    set OUTPATH=%OUTDIR%\!filename!%OUTSUFFIX%
    echo Decrypting %%f into !OUTPATH! >> "%LOGFILE%"
    gpg %GPGARGS% -o "!OUTPATH!" -d -- "%%f"
    if !errorlevel! neq 0 (
        echo Operation failed with return code: %errorlevel% >> "%LOGFILE%"
    ) else (
        echo Operation finished successfully >> "%LOGFILE%"
    )
)
