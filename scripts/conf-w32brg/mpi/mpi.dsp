# Microsoft Developer Studio Project File - Name="mpi" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=mpi - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mpi.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mpi.mak" CFG="mpi - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mpi - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "mpi - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mpi - Win32 Debug"

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
# ADD BASE CPP /nologo /MLd /I "..\..\..\include" /I "..\" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD CPP /nologo /MLd /I "..\..\..\include" /I "..\" /Zi /W3 /Od /D "WIN32" /D "_DEBUG" /D "_LIB" /D "_MBCS" /Gm PRECOMP_VC7_TOBEREMOVED /GZ /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"Debug\mpi.lib" 
# ADD LIB32 /nologo /out:"Debug\mpi.lib" 

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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
# ADD BASE CPP /nologo /ML /I "..\..\..\include" /I "..\" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD CPP /nologo /ML /I "..\..\..\include" /I "..\" /Zi /W3 /D "WIN32" /D "NDEBUG" /D "_LIB" /D "_MBCS" PRECOMP_VC7_TOBEREMOVED /c /GX 
# ADD BASE MTL /nologo /win32 
# ADD MTL /nologo /win32 
# ADD BASE RSC /l 1033 
# ADD RSC /l 1033 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo 
# ADD BSC32 /nologo 
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\bin\mpi.lib" 
# ADD LIB32 /nologo /out:"..\bin\mpi.lib" 

!ENDIF

# Begin Target

# Name "mpi - Win32 Debug"
# Name "mpi - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;def;odl;idl;hpj;bat;asm;asmx"
# Begin Source File

SOURCE=..\..\..\mpi\g10m.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-add.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-bit.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-cmp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-div.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-gcd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-inline.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-inv.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-mpow.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-mul.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-pow.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-scan.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpicoder.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpih-cmp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpih-div.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpih-mul.c
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpiutil.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;inc;xsd"
# Begin Source File

SOURCE=..\..\..\mpi\longlong.h
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-inline.h
# End Source File
# Begin Source File

SOURCE=..\..\..\mpi\mpi-internal.h
# End Source File
# End Group
# Begin Group "Assembler"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\nasm586\mpih-add1.asm

!IF  "$(CFG)" == "mpi - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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
# Begin Source File

SOURCE=..\nasm586\mpih-lshift.asm

!IF  "$(CFG)" == "mpi - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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
# Begin Source File

SOURCE=..\nasm586\mpih-mul1.asm

!IF  "$(CFG)" == "mpi - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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
# Begin Source File

SOURCE=..\nasm586\mpih-mul2.asm

!IF  "$(CFG)" == "mpi - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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
# Begin Source File

SOURCE=..\nasm586\mpih-mul3.asm

!IF  "$(CFG)" == "mpi - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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
# Begin Source File

SOURCE=..\nasm586\mpih-rshift.asm

!IF  "$(CFG)" == "mpi - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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
# Begin Source File

SOURCE=..\nasm586\mpih-sub1.asm

!IF  "$(CFG)" == "mpi - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - 
SOURCE="$(InputPath)"

BuildCmds= \
	nasm -O2 -f win32 -o "$(ProjDir)ir)\$(OutDir)\$(InputName).obj" "$(InputPath)" \


""$(ProjDir)ir)\$(OutDir)\$(InputName).obj"" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mpi - Win32 Release"

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

