# Microsoft Developer Studio Project File - Name="zlib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=zlib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "zlib.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "zlib.mak" CFG="zlib - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "zlib - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "zlib - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "zlib - Win32 Debug"

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
# ADD BASE CPP /nologo /MLd /I "..\" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD CPP /nologo /MLd /I "..\" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\bin\zlib.lib" 
# ADD LIB32 /nologo /out:"..\bin\zlib.lib" 

!ELSEIF  "$(CFG)" == "zlib - Win32 Release"

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
# ADD BASE CPP /nologo /ML /I "..\" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD CPP /nologo /ML /I "..\" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\bin\zlib.lib" 
# ADD LIB32 /nologo /out:"..\bin\zlib.lib" 

!ENDIF

# Begin Target

# Name "zlib - Win32 Debug"
# Name "zlib - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;def;odl;idl;hpj;bat;asm;asmx"
# Begin Source File

SOURCE=..\..\..\zlib\adler32.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\compress.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\crc32.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\deflate.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\infblock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\infcodes.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\inffast.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\inflate.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\inftrees.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\infutil.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\trees.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\uncompr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\zutil.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;inc;xsd"
# Begin Source File

SOURCE=..\..\..\zlib\deflate.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\infblock.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\infcodes.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\inffast.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\inffixed.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\inftrees.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\infutil.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\trees.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\zconf.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\zlib.h
# End Source File
# Begin Source File

SOURCE=..\..\..\zlib\zutil.h
# End Source File
# End Group
# End Target
# End Project

