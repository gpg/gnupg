; w32installer.nsi                                  -*- coding: latin-1; -*-
;                   W32 Installer script
; Copyright (C) 2005 Free Software Foundation, Inc.
;
; This file is free software; as a special exception the author gives
; unlimited permission to copy and/or distribute it, with or without
; modifications, as long as this notice is preserved.
;
; This program is distributed in the hope that it will be useful, but
; WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
; implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

;----------------------------------------------------------------------
; This is an installer script used to create a W32 installer "exe" file
; using NSIS.  It is usually used by the mk-w32-dist script.
;----------------------------------------------------------------------

; We use the modern UI.
!include "MUI.nsh"
!include "StrFunc.nsh"
!include "Sections.nsh"

; -------------
; General stuff
; -------------
Name "GNU Privacy Guard"

!ifdef WITH_WINPT
OutFile "gnupg-w32-${VERSION}.exe"
!else
OutFile "gnupg-w32cli-${VERSION}.exe"
!endif

InstallDir "$PROGRAMFILES\GNU\GnuPG"

InstallDirRegKey HKLM "Software\GNU\GnuPG" "Install Directory"

SetCompressor lzma

VIProductVersion "${PROD_VERSION}"
VIAddVersionKey "ProductName" "GNU Privacy Guard (${VERSION})"
VIAddVersionKey "Comments" \
   "GnuPG is Free Software; you can redistribute it and/or modify  \
    it under the terms of the GNU General Public License. You should  \
    have received a copy of the GNU General Public License along with  \
    this software; if not, see <http://www.gnu.org/licenses/>."
VIAddVersionKey "CompanyName" "Free Software Foundation"
VIAddVersionKey "LegalTrademarks" ""
VIAddVersionKey "LegalCopyright" \
    "Copyright (C) 2007 Free Software Foundation, Inc."
VIAddVersionKey "FileDescription" \
    "GnuPG: Encryption and digital signature tool"
VIAddVersionKey "FileVersion" "${PROD_VERSION}"

; ----------------------
; Variable declarations
; ----------------------

Var MYTMP
Var STARTMENU_FOLDER

; ------------------
; Interface Settings
; ------------------

;;;!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

; Remember the installer language
!define MUI_LANGDLL_REGISTRY_ROOT "HKCU" 
!define MUI_LANGDLL_REGISTRY_KEY "Software\GNU\GnuPG" 
!define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

; -----
; Pages      
; -----

!define MUI_WELCOMEPAGE_TEXT "$(T_About)"

!insertmacro MUI_PAGE_WELCOME


!define MUI_PAGE_HEADER_SUBTEXT "$(T_GPLHeader)"

!define MUI_LICENSEPAGE_TEXT_BOTTOM "$(T_GPLShort)"

!define MUI_LICENSEPAGE_BUTTON "$(^NextBtn)"

!insertmacro MUI_PAGE_LICENSE "COPYING.txt"

!define MUI_PAGE_CUSTOMFUNCTION_SHOW PrintNonAdminWarning
!insertmacro MUI_PAGE_COMPONENTS

Page custom CustomPageOptions

!insertmacro MUI_PAGE_DIRECTORY

!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKCU" 
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\GNU\GnuPG" 
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
  
!insertmacro MUI_PAGE_STARTMENU Application $STARTMENU_FOLDER

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_SHOWREADME "README-W32.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(T_ShowReadme)"
!define MUI_FINISHPAGE_LINK "$(T_FiniLink)"
!define MUI_FINISHPAGE_LINK_LOCATION "http://www.gnupg.org/"
!insertmacro MUI_PAGE_FINISH

  
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES


; -----------------
; i18n Declarations
; -----------------

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

; ------------------
; Installer Sections
; ------------------

!insertmacro MUI_RESERVEFILE_LANGDLL
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS
ReserveFile "opt.ini" 
ReserveFile "COPYING.txt"
ReserveFile "README-W32.txt"
#ReserveFile "${NSISDIR}/Plugins/System.dll"
ReserveFile "${NSISDIR}/Plugins/UserInfo.dll"


${StrStr} # Supportable for Install Sections and Functions
${StrTok} # Supportable for Install Sections and Functions



;InstType "full"
;InstType "minimal"


;----------------------
Section "Base" SecBase
;  SectionIn 1 2 RO
  SectionIn RO

  SetOutPath "$INSTDIR"

  File "gpg.exe"
  File "gpgkeys_finger.exe"
  File "gpgkeys_hkp.exe"
  File "gpgkeys_curl.exe"
  File "gpgkeys_ldap.exe"

  SetOutPath "$INSTDIR\Doc"

  File "README.txt"
  File "README-W32.txt"
  File "COPYING.txt"

  Call InstallIconv

  WriteRegStr HKLM "Software\GNU\GnuPG" "Install Directory" $INSTDIR

SectionEnd ; Section Base

;----------------------
Section "NLS" SecNLS
;  SectionIn 1

  SetOutPath "$INSTDIR\gnupg.nls"

  File "*.mo"

SectionEnd ; Section NLS

;------------------------
Section "Tools" SecTools
;  SectionIn 1

  SetOutPath "$INSTDIR"
  File "gpgsplit.exe"
  File "gpgv.exe"

SectionEnd ; Section Tools

;------------------
!ifdef WITH_WINPT
Section "WinPT" SecWinPT
;  SectionIn 1

  SetOutPath "$INSTDIR"

  File "WinPT.exe"
  File "PTD.dll"
  File "keyserver.conf"

  SetOutPath "$INSTDIR\Doc"

  File "README.winpt.txt"

  WriteRegStr HKCU "Software\GNU\GnuPG" "gpgProgram" "$INSTDIR\gpg.exe"

SectionEnd ; Section WinPT
!endif


;----------------------
Section "Documentation" SecDoc
;  SectionIn 1

  SetOutPath "$INSTDIR\Doc"

  File "gnupg.man"
  File "gpg.man"
  File "gpgv.man"
  File "NEWS.txt"
  File "FAQ.txt"

!ifdef WITH_WINPT
  File "NEWS.winpt.txt"
!endif ; WITH_WINPT

!ifdef WITH_PATCHES
  SetOutPath "$INSTDIR\Src"
  File '*.diff'
!endif

SectionEnd ; Section Documentation


;------------------
!ifdef WITH_SOURCE
Section /o "Source" SecSource

  SetOutPath "$INSTDIR\Src"

  ; Note that we include the uncompressed tarballs because this allows
  ; far better compression results for the distribution.  We might
  ; want to compress it again after installation.

  File "gnupg-${VERSION}.tar"

  File "libiconv-${LIBICONV_VERSION}.tar"

!ifdef WITH_WINPT
  File "winpt-${WINPT_VERSION}.tar"
!endif ; WITH_WINPT

SectionEnd ; Section Source
!endif


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; The last section is a hidden one; used to finish up things.
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Section "-Finish"

  ;;--------------------------
  ;;  Create the uninstaller
  ;;--------------------------
  WriteUninstaller "$INSTDIR\uninst-gnupg.exe"

  StrCpy $MYTMP "Software\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG"
  WriteRegExpandStr HKLM $MYTMP "UninstallString" '"$INSTDIR\uninst-gnupg.exe"'
  WriteRegExpandStr HKLM $MYTMP "InstallLocation" "$INSTDIR"
  WriteRegStr       HKLM $MYTMP "DisplayName"     "GNU Privacy Guard"
  WriteRegStr       HKLM $MYTMP "DisplayIcon"     "$INSTDIR\gpg.exe,0"
  WriteRegStr       HKLM $MYTMP "DisplayVersion"  "${VERSION}"
  WriteRegStr       HKLM $MYTMP "Publisher"       "Free Software Foundation"
  WriteRegStr       HKLM $MYTMP "URLInfoAbout"    "http://www.gnupg.org/"
  WriteRegDWORD     HKLM $MYTMP "NoModify"        "1"
  WriteRegDWORD     HKLM $MYTMP "NoRepair"        "1"


  ;;---------------------
  ;; Create Menu entries
  ;;---------------------
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    
  CreateDirectory "$SMPROGRAMS\$STARTMENU_FOLDER"

  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\GnuPG README.lnk" \
                 "$INSTDIR\Doc\README.txt"
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\GnuPG README.Windows.lnk" \
                 "$INSTDIR\Doc\README-W32.txt"
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\GnuPG NEWS.lnk" \
                 "$INSTDIR\Doc\NEWS.txt"

  SectionGetFlags ${SecDoc} $R0 
  IntOp $R0 $R0 & ${SF_SELECTED} 
  IntCmp $R0 ${SF_SELECTED} 0 +2 
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\GnuPG Manual Page.lnk" \
                 "$INSTDIR\Doc\gpg.man"


!ifdef WITH_WINPT
  SectionGetFlags ${SecWinPT} $R0 
  IntOp $R0 $R0 & ${SF_SELECTED} 
  IntCmp $R0 ${SF_SELECTED} 0 no_winpt_menu 
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\winpt.lnk" \
                 "$INSTDIR\winpt.exe"
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\WinPT README.lnk" \
                 "$INSTDIR\Doc\README.winpt.txt"

  SectionGetFlags ${SecDoc} $R0 
  IntOp $R0 $R0 & ${SF_SELECTED} 
  IntCmp $R0 ${SF_SELECTED} 0 +2 
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\WinPT NEWS.lnk" \
                 "$INSTDIR\Doc\NEWS.winpt.txt"

 no_winpt_menu:
!endif

  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\uninst-gnupg.lnk" \
                 "$INSTDIR\uninst-gnupg.exe"


  !insertmacro MUI_STARTMENU_WRITE_END


  ;;-----------------
  ;; Set the language
  ;;-----------------
  SectionGetFlags ${SecNLS} $R0 
  IntOp $R0 $R0 & ${SF_SELECTED} 
  IntCmp $R0 ${SF_SELECTED} 0 lang_none
  
  !insertmacro MUI_INSTALLOPTIONS_READ $R0 "opt.ini" "Field 1" "ListItems"
  DetailPrint "Available languages: $R0"
  !insertmacro MUI_INSTALLOPTIONS_READ $R1 "opt.ini" "Field 1" "State"
  DetailPrint "Selected language: $R1"

  StrCmp $R1 "" lang_none +1
  ${StrStr} $R2 $R0 $R1 
  StrCmp $R2 "" lang_none +1
  ${StrTok} $R3 $R2 " " "0" "1"
  goto lang_set_finish
 lang_none:
  DetailPrint "No language selected - using default"
  StrCpy $R3 ""
 lang_set_finish:
  DetailPrint "Setting language to: $R3"
  WriteRegStr HKCU "Software\GNU\GnuPG" "Lang" $R3
  ;;

  # Set the Outpath pack so that the README file can be displayed.
  SetOutPath "$INSTDIR"

SectionEnd ; "-Finish"



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Create the section for the uninstaller
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Section "Uninstall"

  ;;------------------------
  ;; Delete files
  ;;------------------------
  Delete "$INSTDIR\gpg.exe"
  Delete "$INSTDIR\gpgkeys_finger.exe"
  Delete "$INSTDIR\gpgkeys_hkp.exe"
  Delete "$INSTDIR\gpgkeys_curl.exe"
  Delete "$INSTDIR\gpgkeys_ldap.exe"

  Delete "$INSTDIR\Doc\README.txt"
  Delete "$INSTDIR\Doc\README-W32.txt"
  Delete "$INSTDIR\Doc\COPYING.txt"
  Delete "$INSTDIR\Doc\COPYING.LIB.txt"
  Delete "$INSTDIR\Doc\README.iconv.txt"

  Delete "$INSTDIR\iconv.dll"

  Delete "$INSTDIR\gnupg.nls\*.mo"

  Delete "$INSTDIR\gpgsplit.exe"
  Delete "$INSTDIR\gpgv.exe"

!ifdef WITH_WINPT
  Delete "$INSTDIR\WinPT.exe"
  Delete "$INSTDIR\PTD.dll"
  Delete "$INSTDIR\Doc\README.winpt.txt"
  Delete "$INSTDIR\Doc\NEWS.winpt.txt"
  Delete "$INSTDIR\Doc\keyserver.conf"
!endif

  Delete "$INSTDIR\Doc\gnupg.man"
  Delete "$INSTDIR\Doc\gpg.man"
  Delete "$INSTDIR\Doc\gpgv.man"
  Delete "$INSTDIR\Doc\NEWS.txt"
  Delete "$INSTDIR\Doc\FAQ.txt"

  Delete "$INSTDIR\Src\gnupg-${VERSION}.tar"
  Delete "$INSTDIR\Src\libiconv-${LIBICONV_VERSION}.tar"
  Delete "$INSTDIR\Src\winpt-${WINPT_VERSION}.tar"
  Delete "$INSTDIR\Src\*.diff"

  Delete "$INSTDIR\uninst-gnupg.exe"

  ;;------------------------
  ;; Delete directories
  ;;------------------------
  RMDir "$INSTDIR\Doc"
  RMDir "$INSTDIR\Src"
  RMDir "$INSTDIR\gnupg.nls"
  RMDir "$INSTDIR"


  ;;---------------------------------------------------
  ;; Delete the menu entries and any empty parent menus
  ;;---------------------------------------------------
  !insertmacro MUI_STARTMENU_GETFOLDER Application $MYTMP
  Delete "$SMPROGRAMS\$MYTMP\*.lnk"
  StrCpy $MYTMP "$SMPROGRAMS\$MYTMP"
  startMenuDeleteLoop:
    ClearErrors
    RMDir $MYTMP
    GetFullPathName $MYTMP "$MYTMP\.."
    IfErrors startMenuDeleteLoopDone
    StrCmp $MYTMP $SMPROGRAMS startMenuDeleteLoopDone startMenuDeleteLoop
  startMenuDeleteLoopDone:


  ;;-----------------------
  ;;  Cleanup the registry
  ;;-----------------------
  DeleteRegValue HKCU "Software\GNU\GnuPG" "Start Menu Folder"
  DeleteRegValue HKLM "Software\GNU\GnuPG" "Install Directory"
  DeleteRegKey /ifempty HKLM "Software\GNU\GnuPG"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG"

SectionEnd ; Uninstall


; ---------
; Functions
; ---------

Function .onInit
  # We can't use System.dll anymore becuase it has bee removed from
  # Debian due to an inability to build using FS.  We should use the
  # use our own DLL as we do with gpg4win.
  #System::Call 'kernel32::CreateMutexA(i 0, i 0, t "GnuPGInst") i .r1 ?e'
  #Pop $R0
  #StrCmp $R0 0 +3
  # MessageBox MB_OK "An instance of the installer is already running."
  # Abort

  ;;!define MUI_LANGDLL_ALWAYSSHOW
  !insertmacro MUI_LANGDLL_DISPLAY

  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "opt.ini"

FunctionEnd 


Function un.onInit 

  !insertmacro MUI_UNGETLANGUAGE
  
FunctionEnd


;; Check whether the current user is in the Administrator group or
;; an OS version without the need for an Administrator is in use.
;; Print a warning if this is not the case.
Function PrintNonAdminWarning
  ClearErrors
  UserInfo::GetName
  IfErrors leave
  Pop $0
  UserInfo::GetAccountType
  Pop $1
  StrCmp $1 "Admin" leave +1
  MessageBox MB_OK "$(T_AdminNeeded)"

 leave:
FunctionEnd


Function CustomPageOptions  
  SectionGetFlags ${SecNLS} $R0 
  IntOp $R0 $R0 & ${SF_SELECTED} 
  IntCmp $R0 ${SF_SELECTED} show 
 
  Abort 
 
 show: 
  !insertmacro MUI_HEADER_TEXT "$(T_InstallOptions)" "$(T_SelectLanguage)"
  !insertmacro MUI_INSTALLOPTIONS_READ $R0 "opt.ini" "Field 1" "ListItems"
  ReadRegStr $R1 HKCU "Software\GNU\GnuPG" "Lang" 
  StrCmp $R1 "" use_default +1
  ${StrStr} $R2 $R0 "$R1 - " 
  StrCmp $R2 "" +1 set_lang
 use_default:
  StrCpy $R2 "$(T_langid) - $(T_langname)"
 set_lang:
  ${StrTok} $R3 $R2 "|" "0" "1"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "opt.ini" "Field 1" "State" $R3

  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "opt.ini"

FunctionEnd


; Install iconv.dll if it has not been installed on the system.
Function InstallIconv

  ; First delete a iconv DLL already installed in the target directory.
  ; This is required to detect a meanwhile globally installed dll.
  Delete "$INSTDIR\iconv.dll"
  ClearErrors
  GetDllVersion "iconv.dll" $R0 $R1
  IfErrors 0 +3
    DetailPrint "iconv.dll is not installed."
    goto InstallIconv

  IntOp $R2 $R0 / 0x00010000
  IntOp $R3 $R0 & 0x0000FFFF
  IntOp $R4 $R1 / 0x00010000
  IntOp $R5 $R1 & 0x0000FFFF
  StrCpy $0 "$R2.$R3.$R4.$R5"

  DetailPrint "iconv.dll version is $0"

  IntCmp $R2 1 0 IconvTooOld
  IntCmp $R3 9 0 IconvTooOld
  return

 IconvTooOld:
    DetailPrint "The installed iconv.dll is too old."

 InstallIconv:
  SetOutPath "$INSTDIR"
  File "iconv.dll"

  SetOutPath "$INSTDIR\doc"
  File "COPYING.LIB.txt"
  File "README.iconv.txt"

FunctionEnd


; ------------
; Descriptions
; ------------

; The list of language IDs and corresponding Latin-1 names.  Note that
; this mapping needs to match the one in the mk-w32-dist script, so
; that they are usable to get a default value for then ListItems of
; opt.ini.
LangString T_langid   ${LANG_ENGLISH} "en"
LangString T_langname ${LANG_ENGLISH} "English"
LangString T_langid   ${LANG_GERMAN}  "de"
LangString T_langname ${LANG_GERMAN}  "Deutsch"

; The About string as displayed on the first page.
LangString T_About ${LANG_ENGLISH} \
  "GnuPG is GNU's tool for secure communication and data storage. \
  It can be used to encrypt data and to create digital signatures. \
  It includes an advanced key management facility and is compliant \
  with the proposed OpenPGP Internet standard as described in RFC2440. \
  \r\n\r\n$_CLICK \
  \r\n\r\n\r\n\r\n\r\nThis is GnuPG version ${VERSION}\r\n\
  built on $%BUILDINFO%\r\n\
  file version ${PROD_VERSION}"
LangString T_About ${LANG_GERMAN} \
  "GnuPG is das Werkzeug aus dem GNU Projekt zur sicheren Kommunikation \
   sowie zum sicheren Speichern von Daten. \
   \r\n\r\n$_CLICK \
   \r\n\r\n\r\n\r\n\r\nDies ist GnuPG Version ${VERSION}\r\n\
   erstellt am $%BUILDINFO%\r\n\
   Dateiversion ${PROD_VERSION}"

; Startup page
LangString T_GPLHeader ${LANG_ENGLISH} \
  "This software is licensed under the terms of the GNU General Public \
   License (GPL) which guarantees your freedom to share and change Free \
   Software."
LangString T_GPLHeader ${LANG_GERMAN}} \
  "Diese Software ist unter der GNU General Public License \
   (GPL) lizensiert; dies gibt Ihnen die Freiheit, sie \
   zu ändern und weiterzugeben."

LangString T_GPLShort ${LANG_ENGLISH} \
  "In short: You are allowed to run this software for any purpose. \
   You may distribute it as long as you give the recipients the same \
   rights you have received."
LangString T_GPLShort ${LANG_GERMAN} \
  "In aller Kürze: Sie haben das Recht, die Software zu jedem Zweck \
   einzusetzen.  Sie können die Software weitergeben, sofern Sie dem \
   Empfänger dieselben Rechte einräumen, die auch Sie erhalten haben."


; Finish page
LangString T_FiniLink ${LANG_ENGLISH} \
  "Visit the GnuPG website for latest news and support"
LangString T_FiniLink ${LANG_GERMAN}} \
  "Zur GnuPG Website mit Neuigkeiten und Hilfsangeboten"

; From Function PrintNonAdminWarning
LangString T_AdminNeeded ${LANG_ENGLISH} \
   "Warning: Administrator permissions required for a successful installation"
LangString T_AdminNeeded ${LANG_GERMAN} \
   "Warnung: Administrator Reche werden für eine erfolgreiche \
    Installation benötigt."


; Installation options like language used for GnuPG
LangString T_InstallOptions ${LANG_ENGLISH} "Install Options"
LangString T_InstallOptions ${LANG_GERMAN}  "Installationsoptionen"

LangString T_SelectLanguage ${LANG_ENGLISH} "GnuPG Language Selection"
LangString T_SelectLanguage ${LANG_German}  "Auswahl der Sprache für GnuPG"

; This text is used on the finish page.
LangString T_ShowReadme ${LANG_ENGLISH} "Show the README file"
LangString T_ShowReadme ${LANG_GERMAN} "Die README Datei anzeigen"

; Section names
LangString DESC_SecBase ${LANG_ENGLISH} \
      "The basic files used for the standard OpenPGP protocol"
LangString DESC_SecBase ${LANG_GERMAN} \
      "Die Basis Dateien zur Benutzung des OpenPGP Protokolls"

Langstring DESC_SecNLS ${LANG_ENGLISH} \
      "Support for languages other than English"
LangString DESC_SecNLS ${LANG_GERMAN} \
      "Unterstützung für weitere Sprachen neben Englisch"

LangString DESC_SecTools ${LANG_ENGLISH} \
      "Extra tools like gpgv and gpgsplit"
LangString DESC_SecTools ${LANG_GERMAN} \
      "Weitere Tools wie gpgv und gpgsplit"

!ifdef WITH_WINPT
LangString DESC_SecWinPT ${LANG_ENGLISH} \
      "The Windows Privacy Tray (WinPT)"
LangString DESC_SecWinPT ${LANG_GERMAN} \
      "Der Windows Privacy Tray (WinPT)"
!endif

LangString DESC_SecDoc ${LANG_ENGLISH} \
      "Manual pages and a FAQ"
LangString DESC_SecDoc ${LANG_GERMAN} \
      "Handbuchseiten und eine FAQ"

LangString DESC_SecSource ${LANG_ENGLISH} \
      "Quelltextdateien"
LangString DESC_SecSource ${LANG_GERMAN} \
      "Source files"



;-------------------------------------
; Associate section names with strings
;--------------------------------------
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecBase} $(DESC_SecBase)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecNLS} $(DESC_SecNLS)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTools} $(DESC_SecTools)
!ifdef WITH_WINPT
  !insertmacro MUI_DESCRIPTION_TEXT ${SecWinPT} $(DESC_SecWinPT)
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDoc} $(DESC_SecDoc)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

