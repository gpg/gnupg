# Microsoft Developer Studio Project File - Name="cipher" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=cipher - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "cipher.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "cipher.mak" CFG="cipher - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cipher - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "cipher - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cipher - Win32 Debug"

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
# ADD BASE CPP /nologo /MLd /I "..\" /I "..\..\..\cipher" /I "..\..\..\include" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD CPP /nologo /MLd /I "..\" /I "..\..\..\cipher" /I "..\..\..\include" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\bin\cipher.lib" 
# ADD LIB32 /nologo /out:"..\bin\cipher.lib" 

!ELSEIF  "$(CFG)" == "cipher - Win32 Release"

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
# ADD BASE CPP /nologo /ML /I "..\" /I "..\..\..\cipher" /I "..\..\..\include" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD CPP /nologo /ML /I "..\" /I "..\..\..\cipher" /I "..\..\..\include" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\bin\cipher.lib" 
# ADD LIB32 /nologo /out:"..\bin\cipher.lib" 

!ENDIF

# Begin Target

# Name "cipher - Win32 Debug"
# Name "cipher - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;def;odl;idl;hpj;bat;asm;asmx"
# Begin Source File

SOURCE=..\aescrypt.c

!IF  "$(CFG)" == "cipher - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "cipher - Win32 Release"

# PROP Exclude_From_Build 1

!ENDIF

# End Source File
# Begin Source File

SOURCE=..\aeskey.c
# End Source File
# Begin Source File

SOURCE=..\aestab.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\blowfish.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\cast5.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\cipher.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\des.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\dsa.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\dynload.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\elgamal.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\g10c.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\idea-stub.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\md.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\md5.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\primegen.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\pubkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\random.c
# End Source File
# Begin Source File

SOURCE=..\rijndael2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rmd160.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rndegd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rndlinux.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rndunix.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rndw32.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rsa.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\sha1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\sha256.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\sha512.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\smallprime.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\tiger.c
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\twofish.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;inc;xsd"
# Begin Source File

SOURCE=..\aes.h
# End Source File
# Begin Source File

SOURCE=..\aesopt.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\algorithms.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\bithelp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\dsa.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\elgamal.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rand-internal.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\random.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rmd.h
# End Source File
# Begin Source File

SOURCE=..\..\..\cipher\rsa.h
# End Source File
# End Group
# Begin Group "Assembler"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\aescrypt.asm

!IF  "$(CFG)" == "cipher - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cipher - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF

# End Source File
# End Group
# End Target
# End Project

