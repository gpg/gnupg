@echo off
cd /d d:\

set TARGET=gnupg-test

set GNUPGHOME=c:/%TARGET%/tests/openpgp
c:/%TARGET%/gpg-connect-agent.exe killagent /bye
rem is there a nicer way to sleep?
ping -n 1 localhost > nul
set GNUPGHOME=

rmdir /q /s c:\%TARGET%
mkdir c:\%TARGET%
xcopy /q /s d:\gnupg c:\%TARGET%

set GPGSCM_PATH=c:/%TARGET%/tests/gpgscm;c:/%TARGET%/tests/openpgp
set EXEEXT=.exe
set srcdir=/%TARGET%/tests/openpgp
set BIN_PREFIX=c:/%TARGET%

cd /d c:\%TARGET%
c:\%TARGET%\gpgscm.exe --verbose tests/gpgscm/t-child.scm

cd /d c:\%TARGET%\tests\openpgp
c:\%TARGET%\gpgscm.exe run-tests.scm
