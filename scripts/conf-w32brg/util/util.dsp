# Microsoft Developer Studio Project File - Name="util" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=util - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "util.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "util.mak" CFG="util - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "util - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "util - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "util - Win32 Debug"

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
# ADD BASE CPP /nologo /MLd /I "..\" /I "..\..\..\include" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD CPP /nologo /MLd /I "..\" /I "..\..\..\include" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\bin\util.lib" 
# ADD LIB32 /nologo /out:"..\bin\util.lib" 

!ELSEIF  "$(CFG)" == "util - Win32 Release"

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
# ADD BASE CPP /nologo /ML /I "..\" /I "..\..\..\include" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD CPP /nologo /ML /I "..\" /I "..\..\..\include" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\bin\util.lib" 
# ADD LIB32 /nologo /out:"..\bin\util.lib" 

!ENDIF

# Begin Target

# Name "util - Win32 Debug"
# Name "util - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;def;odl;idl;hpj;bat;asm;asmx"
# Begin Source File

SOURCE=..\..\..\util\argparse.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\dotlock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\errors.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\fileutil.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\g10u.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\http.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\iobuf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\logger.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\memory.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\miscutil.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\secmem.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\simple-gettext.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\strgutil.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\ttyio.c
# End Source File
# Begin Source File

SOURCE=..\..\..\util\w32reg.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;inc;xsd"
# End Group
# End Target
# End Project

