; w32installer.nsi - W32 Installer definition      -*- lisp -*-
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

; TODO:
; - Display credit for the installer
; - Provide the location of the corresponding source
; - Check for iconv.dll and optionalkly install or download it.
; - Allow inclusion of the source into the installer.
; - Translate all strings
; - Setup the home directory and check for old (c:/gnupg located)
;   versions of the program

; We use the modern UI.
!include "MUI.nsh"

; -------------
; General stuff
; -------------
Name "GNU Privacy Guard"

OutFile "gnupg-w32cli-${VERSION}.exe"

InstallDir "$PROGRAMFILES\GNU\GnuPG"

InstallDirRegKey HKCU "Software\GNU\GnuPG" ""

SetCompressor lzma

ReserveFile "COPYING.txt"

VIProductVersion "${PROD_VERSION}"
VIAddVersionKey "ProductName" "GNU Privacy Guard (${VERSION})"
VIAddVersionKey "Comments" \
   "GnuPG is Free Software; you can redistribute it and/or modify  \
    it under the terms of the GNU General Public License. You should  \
    have received a copy of the GNU General Public License along with  \
    this software; if not, write to the Free Software Foundation, Inc.,  \
    59 Temple Place - Suite 330, Boston, MA 02111-1307, USA"
VIAddVersionKey "CompanyName" "Free Software Foundation"
VIAddVersionKey "LegalTrademarks" ""
VIAddVersionKey "LegalCopyright" \
    "Copyright (C) 2005 Free Software Foundation, Inc."
VIAddVersionKey "FileDescription" \
    "GnuPG: Encryption and digital signature tool"
VIAddVersionKey "FileVersion" "${PROD_VERSION}"


; ------------------
; Interface Settings
; ------------------

!define MUI_ABORTWARNING
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


!define MUI_PAGE_HEADER_SUBTEXT \
  "This software is licensed under the terms of the GNU General Public \
   License (GPL) which guarantees your freedom to share and change Free \
   Software."

!define MUI_LICENSEPAGE_TEXT_BOTTOM \
  "In short: You are allowed to run this software for any purpose. \
   You may distribute it as long as you give the recipients the same \
   rights you have received."

!define MUI_LICENSEPAGE_BUTTON "$(^NextBtn)"

!insertmacro MUI_PAGE_LICENSE "COPYING.txt"


!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_SHOWREADME "README.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(T_ShowReadme)"
!define MUI_FINISHPAGE_LINK "Goto the GnuPG website"
!define MUI_FINISHPAGE_LINK_LOCATION "http://www.gnupg.org"
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

;InstType "full"
;InstType "minimal"

;----------------------
Section "Base" SecBase
;  SectionIn 1 2 RO
  SectionIn RO

  SetOutPath "$INSTDIR"

  File "README.txt"
  File "README.W32"
  File "COPYING.txt"
  File "gpg.exe"
  File "gpgkeys_finger.exe"
  File "gpgkeys_hkp.exe"
  File "gpgkeys_http.exe"
  File "gpgkeys_ldap.exe"
  File "*.mo"

  WriteRegStr HKCU "Software\GNU\GnuPG" "" $INSTDIR

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
SectionEnd ; Section Base

;------------------------
Section "Tools" SecTools
;  SectionIn 1

  File "gpgsplit.exe"
  File "gpgv.exe"

SectionEnd ; Section Tools

;----------------------
Section "Documentation" SecDoc
;  SectionIn 1

  File "gnupg.man"
  File "gpg.man"
  File "gpgv.man"
  File "NEWS.txt"
  File "FAQ.txt"

SectionEnd ; Section Documentation


;------------------
!ifdef WITH_SOURCE
Section "Source" SecSource

   ; Note that we include the uncompressed tarball because this allows
   ; far better compression results for the distribution.  We might
   ; want to compress it again after installation.
   File "gnupg-1.4.0.tar"

SectionEnd ; Section Source
!endif


;----------------------
Section "-Finish" 

  ClearErrors
  GetDllVersion "iconv.dll" $R0 $R1
  IfErrors 0 +3
    MessageBox MB_OK \
       "iconv.dll is not installed.$\r$\n \
        It is highy suggested to install  \
        this DLL to help with character set conversion.$\r$\n$\r$\n \
        See http://www.gnupg.org/download/iconv.html  for instructions."
    Return

  IntOp $R2 $R0 / 0x00010000
  IntOp $R3 $R0 & 0x0000FFFF
  IntOp $R4 $R1 / 0x00010000
  IntOp $R5 $R1 & 0x0000FFFF
  StrCpy $0 "$R2.$R3.$R4.$R5"

  DetailPrint "iconv.dll version is $0"

  IntCmp $R2 1 0 IconvTooOld
  IntCmp $R3 9 0 IconvTooOld
  goto +3
 IconvTooOld:
    MessageBox MB_OK \
      "The installed iconv.dll is too old.$\r$\n \
       We require at least version 1.9.0.0  (installed: $0).$\r$\n \
       It is highly suggested to install an updated DLL to help  \
       with character set conversion.$\r$\n$\r$\n \
       See http://www.gnupg.org/download/iconv.html  for instructions."


SectionEnd


;------------------
Section "Uninstall"

  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\README.W32"
  Delete "$INSTDIR\COPYING.txt"
  Delete "$INSTDIR\gpg.exe"
  Delete "$INSTDIR\gpgkeys_finger.exe"
  Delete "$INSTDIR\gpgkeys_hkp.exe"
  Delete "$INSTDIR\gpgkeys_http.exe"
  Delete "$INSTDIR\gpgkeys_ldap.exe"
  Delete "$INSTDIR\*.mo"
  Delete "$INSTDIR\gpgsplit.exe"
  Delete "$INSTDIR\gpgv.exe"
  Delete "$INSTDIR\gnupg.man"
  Delete "$INSTDIR\gpg.man"
  Delete "$INSTDIR\gpgv.man"
  Delete "$INSTDIR\NEWS.txt"
  Delete "$INSTDIR\FAQ.txt"

  Delete "$INSTDIR\Uninstall.exe"

  RMDir "$INSTDIR"

  DeleteRegKey /ifempty HKCU "Software\GNU\GnuPG"

SectionEnd ; Uninstall


; ---------
; Functions
; ---------

Function .onInit

  !insertmacro MUI_LANGDLL_DISPLAY

FunctionEnd 


Function un.onInit

  !insertmacro MUI_UNGETLANGUAGE
  
FunctionEnd


; ------------
; Descriptions
; ------------


LangString T_About ${LANG_ENGLISH} \
  "GnuPG is GNU's tool for secure communication and data storage. \
  It can be used to encrypt data and to create digital signatures. \
  It includes an advanced key management facility and is compliant \
  with the proposed OpenPGP Internet standard as described in RFC2440."
LangString T_About ${LANG_GERMAN} \
  "GnuPG is das Werzeug aus dem GNU Projekt zur sicheren Kommunikation \
   sowie zum sicheren Speichern von Daten."
LangString T_ShowReadme ${LANG_ENGLISH} "Show the README file"
LangString T_ShowReadme ${LANG_GERMAN} "Die README Datei anzeigen"


LangString DESC_SecBase ${LANG_ENGLISH} \
      "The basic files used for the standard OpenPGP protocol"
LangString DESC_SecBase ${LANG_GERMAN} \
      "Die Basis Dateien zur Benutzung des OpenPGP Protokolls"

LangString DESC_SecTools ${LANG_ENGLISH} \
      "Extra tools like gpgv and gpgsplit"
LangString DESC_SecTools ${LANG_GERMAN} \
      "Weitere Tools wie gpgv und gpgsplit"

LangString DESC_SecDoc ${LANG_ENGLISH} \
      "Manual pages and a FAQ"
LangString DESC_SecDoc ${LANG_GERMAN} \
      "Handbuchseiten und eine FAQ"

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecBase} $(DESC_SecBase)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTools} $(DESC_SecTools)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDoc} $(DESC_SecDoc)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

