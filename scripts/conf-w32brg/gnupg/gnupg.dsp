# Microsoft Developer Studio Project File - Name="gnupg" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=gnupg - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "gnupg.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gnupg.mak" CFG="gnupg - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gnupg - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "gnupg - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "gnupg - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MLd /I "..\" /I "..\..\..\include" /I "..\..\..\zlib" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD CPP /nologo /MLd /I "..\" /I "..\..\..\include" /I "..\..\..\zlib" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib /nologo /out:"..\bin\gpg.exe" /incremental:yes /libpath:"..\bin" /debug /pdb:"Debug\gpg.pdb" /pdbtype:sept /subsystem:console /machine:ix86 
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib /nologo /out:"..\bin\gpg.exe" /incremental:yes /libpath:"..\bin" /debug /pdb:"Debug\gpg.pdb" /pdbtype:sept /subsystem:console /machine:ix86 

!ELSEIF  "$(CFG)" == "gnupg - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /ML /I "..\" /I "..\..\..\include" /I "..\..\..\zlib" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD CPP /nologo /ML /I "..\" /I "..\..\..\include" /I "..\..\..\zlib" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib /nologo /out:"..\bin\gpg.exe" /incremental:no /debug /pdb:"Release\gpg.pdb" /pdbtype:sept /subsystem:console /opt:ref /opt:icf /machine:ix86 
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib /nologo /out:"..\bin\gpg.exe" /incremental:no /debug /pdb:"Release\gpg.pdb" /pdbtype:sept /subsystem:console /opt:ref /opt:icf /machine:ix86 

!ENDIF

# Begin Target

# Name "gnupg - Win32 Debug"
# Name "gnupg - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;def;odl;idl;hpj;bat;asm;asmx"
# Begin Source File

SOURCE=..\..\..\g10\armor.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\build-packet.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\cipher.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\comment.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\compress-bz2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\compress.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\dearmor.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\decrypt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\delkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\encode.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\encr-data.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\exec.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\export.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\free-packet.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\g10.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\getkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\helptext.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\hkp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\import.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\kbnode.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keydb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keyedit.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keygen.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keyid.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keylist.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keyring.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keyserver.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\mainproc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\mdfilter.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\misc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\mkdtemp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\openfile.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\parse-packet.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\passphrase.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\photoid.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\pipemode.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\pkclist.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\plaintext.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\progress.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\pubkey-enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\revoke.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\seckey-cert.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\seskey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\sig-check.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\sign.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\signal.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\skclist.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\status.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\tdbdump.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\tdbio.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\textfilter.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\trustdb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\verify.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;inc;xsd"
# Begin Source File

SOURCE=..\..\..\g10\exec.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\filter.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\global.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\hkp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keydb.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keyring.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\keyserver-internal.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\main.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\options.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\packet.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\photoid.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\status.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\tdbio.h
# End Source File
# Begin Source File

SOURCE=..\..\..\g10\trustdb.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\bin\cipher.lib
# End Source File
# Begin Source File

SOURCE=..\..\..\..\bzip2-1.0.2\libbz2\Release\libbz2.lib
# End Source File
# Begin Source File

SOURCE=..\bin\mpi.lib
# End Source File
# Begin Source File

SOURCE=..\bin\util.lib
# End Source File
# Begin Source File

SOURCE=..\bin\zlib.lib
# End Source File
# End Target
# End Project

