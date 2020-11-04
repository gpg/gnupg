# inst.nsi - Installer for GnuPG on Windows.      -*- coding: latin-1; -*-
# Copyright (C) 2005, 2014 g10 Code GmbH
#               2017 Intevation GmbH
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Macros to provide for invocation:
#  INST_DIR
#  INST6_DIR
#  BUILD_DIR
#  TOP_SRCDIR
#  W32_SRCDIR
#  BUILD_ISODATE   - the build date, e.g. "2014-10-31"
#  BUILD_DATESTR   - ditto w/o '-',  e.g. "20141031"
#  NAME
#  VERSION
#  PROD_VERSION
#
#  WITH_GUI        - Include the GPA GUI

!cd "${INST_DIR}"
!addincludedir "${W32_SRCDIR}"
!addplugindir "${BUILD_DIR}"

# The package name and version.  PRETTY_PACKAGE is a user visible name
# only while PACKAGE is useful for filenames etc.  PROD_VERSION is the
# product version and needs to be in the format "MAJ.MIN.MIC.BUILDNR".
!define PACKAGE "gnupg"
!define PACKAGE_SHORT "gnupg"
!define PRETTY_PACKAGE "GNU Privacy Guard"
!define PRETTY_PACKAGE_SHORT "GnuPG"
!define COMPANY "The GnuPG Project"
!define COPYRIGHT "Copyright (C) 2017 The GnuPG Project"
!define DESCRIPTION "GnuPG: The GNU Privacy Guard for Windows"

!define INSTALL_DIR "GnuPG"

!define WELCOME_TITLE_ENGLISH \
 "Welcome to the installation of GnuPG"

!define WELCOME_TITLE_GERMAN \
 "Willkommen bei der Installation von GnuPG"

!define ABOUT_ENGLISH \
 "GnuPG is the mostly used software for mail and data encryption. \
  GnuPG can be used to encrypt data and to create digital signatures. \
  GnuPG includes an advanced key management facility and is compliant \
  with the OpenPGP Internet standard as described in RFC-4880. \
  \r\n\r\n$_CLICK \
  \r\n\r\n\r\n\r\n\r\nThis is GnuPG version ${VERSION}.\r\n\
  File version: ${PROD_VERSION}\r\n\
  Release date: ${BUILD_ISODATE}"
!define ABOUT_GERMAN \
 "GnuPG is die häufigst verwendete Software zur Mail- und Datenverschlüsselung.\
   \r\n\r\n$_CLICK \
   \r\n\r\n\r\n\r\n\r\nDies ist GnuPG Version ${VERSION}.\r\n\
   Dateiversion: ${PROD_VERSION}\r\n\
   Releasedatum: ${BUILD_ISODATE}"


# The copyright license of the package.  Define only one of these.
!define LICENSE_GPL

# Select the best compression algorithm available.  The dictionary
# size is the default (8 MB).
!ifndef SOURCES
SetCompressor lzma
# SetCompressorDictSize 8
!endif

# We use the modern UI.
!include "MUI.nsh"

# Some helper some
!include "LogicLib.nsh"
!include "x64.nsh"

# We support user mode installation but prefer system wide
!define MULTIUSER_EXECUTIONLEVEL Highest
!define MULTIUSER_MUI
!define MULTIUSER_INSTALLMODE_COMMANDLINE
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "Software\${PACKAGE_SHORT}"
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME ""
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_KEY "Software\${PACKAGE_SHORT}"
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_VALUENAME "Install Directory"
!define MULTIUSER_INSTALLMODE_INSTDIR "${PACKAGE_SHORT}"
!include "MultiUser.nsh"

# Set the package name.  Note that this name should not be suffixed
# with the version because this would get displayed in the start menu.
# Given that a slash in the name troubles Windows startmenu creation
# we set the Startmenu explicit below.
Name "${PRETTY_PACKAGE}"

# Set the output filename.
OutFile "${NAME}-${VERSION}_${BUILD_DATESTR}.exe"

#Fixme: Do we need a logo?
#Icon "${TOP_SRCDIR}/doc/logo/gnupg-logo-icon.ico"
#UninstallIcon "${TOP_SRCDIR}/doc/logo/gnupg-logo-icon.ico"

# Set the installation directory.
!ifndef INSTALL_DIR
!define INSTALL_DIR "GnuPG"
!endif
InstallDir "$PROGRAMFILES\${INSTALL_DIR}"

# Add version information to the file properties.
VIProductVersion "${PROD_VERSION}"
VIAddVersionKey "ProductName" "${PRETTY_PACKAGE_SHORT} (${VERSION})"
VIAddVersionKey "Comments" \
   "GnuPG is Free Software; you can redistribute it  \
    and/or modify it under the terms of the GNU General Public License.  \
    You should have received a copy of the GNU General Public License  \
    along with this software; if not, write to the Free Software  \
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,  \
    MA 02110-1301, USA"
VIAddVersionKey "CompanyName" "${COMPANY}"
VIAddVersionKey "LegalTrademarks" ""
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileDescription" "${DESCRIPTION}"
VIAddVersionKey "FileVersion" "${PROD_VERSION}"

# Interface Settings

# !define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${W32_SRCDIR}\gnupg-logo-150x57.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${W32_SRCDIR}\gnupg-logo-164x314.bmp"

# Remember the installer language
!define MUI_LANGDLL_REGISTRY_ROOT "HKCU"
!define MUI_LANGDLL_REGISTRY_KEY "Software\GnuPG"
!define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

#
# The list of wizard pages.
#
!define MUI_WELCOMEPAGE_TITLE "$(T_WelcomeTitle)"
!define MUI_WELCOMEPAGE_TEXT  "$(T_About)"
!insertmacro MUI_PAGE_WELCOME

!define MUI_LICENSEPAGE_BUTTON "$(^NextBtn)"
!define MUI_PAGE_HEADER_SUBTEXT "$(T_GPLHeader)"
!define MUI_LICENSEPAGE_TEXT_BOTTOM "$(T_GPLShort)"
!insertmacro MUI_PAGE_LICENSE "${TOP_SRCDIR}/COPYING"

!define MUI_PAGE_CUSTOMFUNCTION_SHOW PrintNonAdminWarning
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE CheckExistingVersion
!insertmacro MUI_PAGE_COMPONENTS

# We don't have MUI_PAGE_DIRECTORY

!ifdef WITH_GUI

Page custom CustomPageOptions

Var STARTMENU_FOLDER

!define MUI_PAGE_CUSTOMFUNCTION_PRE CheckIfStartMenuWanted
!define MUI_STARTMENUPAGE_NODISABLE
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "SHCTX"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\GnuPG"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
# We need to set the Startmenu name explicitly because a slash in the
# name is not possible.
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "GnuPG"

!insertmacro MUI_PAGE_STARTMENU Application $STARTMENU_FOLDER

!endif

!define MUI_PAGE_CUSTOMFUNCTION_PRE PrintCloseOtherApps
!insertmacro MUI_PAGE_INSTFILES

#!define MUI_PAGE_CUSTOMFUNCTION_PRE ShowFinalWarnings
!define MUI_FINISHPAGE_SHOWREADME "README.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(T_ShowReadme)"
#!define MUI_FINISHPAGE_RUN
#!define MUI_FINISHPAGE_RUN_FUNCTION RunOnFinish
#!define MUI_FINISHPAGE_RUN_TEXT "$(T_RunKeyManager)"
#!define MUI_FINISHPAGE_RUN_NOTCHECKED
!define MUI_FINISHPAGE_LINK "$(T_MoreInfo)"
!define MUI_FINISHPAGE_LINK_LOCATION "$(T_MoreInfoURL)"
!insertmacro MUI_PAGE_FINISH


# Uninstaller pages.

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES


#Page license
#Page components
#Page directory
#Page instfiles
#UninstPage uninstConfirm
#UninstPage instfiles


# Language support.  This has to be done after defining the pages, but
# before defining the translation strings.  Confusing.

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

!insertmacro MUI_RESERVEFILE_LANGDLL
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS
ReserveFile "${BUILD_DIR}\g4wihelp.dll"
ReserveFile "${W32_SRCDIR}\gnupg-logo-150x57.bmp"
ReserveFile "${W32_SRCDIR}\gnupg-logo-164x314.bmp"
ReserveFile "${TOP_SRCDIR}\COPYING"
ReserveFile "${W32_SRCDIR}\inst-options.ini"

# Language support

LangString T_LangCode ${LANG_ENGLISH} "en"
LangString T_LangCode ${LANG_GERMAN}  "de"


# The WelcomeTitle is displayed on the first page.
LangString T_WelcomeTitle ${LANG_ENGLISH} "${WELCOME_TITLE_ENGLISH}"
LangString T_WelcomeTitle ${LANG_GERMAN} "${WELCOME_TITLE_GERMAN}"

# The About string as displayed on the first page.
LangString T_About ${LANG_ENGLISH} "${ABOUT_ENGLISH}"
LangString T_About ${LANG_GERMAN} "${ABOUT_GERMAN}"

# Startup page
LangString T_GPLHeader ${LANG_ENGLISH} \
  "This software is licensed under the terms of the GNU General Public \
   License (GNU GPL)."
LangString T_GPLHeader ${LANG_GERMAN}} \
  "Diese Software ist unter der GNU General Public License \
   (GNU GPL) lizensiert."

LangString T_GPLShort ${LANG_ENGLISH} \
  "In short: You are allowed to run this software for any purpose. \
   You may distribute it as long as you give the recipients the same \
   rights you have received."
LangString T_GPLShort ${LANG_GERMAN} \
  "In aller Kürze: Sie haben das Recht, die Software zu jedem Zweck \
   einzusetzen.  Sie können die Software weitergeben, sofern Sie dem \
   Empfänger dieselben Rechte einräumen, die auch Sie erhalten haben."

LangString T_RunKeyManager ${LANG_ENGLISH} \
   "Run the key manager"
LangString T_RunKeyManager ${LANG_GERMAN} \
   "Die Schlüsselverwaltung aufrufen"

LangString T_MoreInfo ${LANG_ENGLISH} \
   "Click here to see how to help the GnuPG Project"
LangString T_MoreInfo ${LANG_GERMAN} \
   "Hier klicken um dem GnuPG Projekt zu zu helfen"
LangString T_MoreInfoURL ${LANG_ENGLISH} "https://gnupg.org/donate"
LangString T_MoreInfoURL ${LANG_GERMAN}  "https://gnupg.org/donate"

LangString T_ShowReadme ${LANG_ENGLISH} \
   "Show the README file"
LangString T_ShowReadme ${LANG_GERMAN} \
   "Die README Datei anzeigen"

LangString T_NoKeyManager ${LANG_ENGLISH} \
   "No key manager has been installed, thus we can't run one now."
LangString T_NoKeyManager ${LANG_GERMAN} \
   "Es wurde keine Schlüsselverwaltung installiert. \
    Deswegen kann sie jetzt auch nicht ausgeführt werden."

# Functions

# Custom functions and macros for this installer.
LangString T_AlreadyRunning ${LANG_ENGLISH} \
   "An instance of this installer is already running."
LangString T_AlreadyRunning ${LANG_GERMAN} \
   "Ein Exemplar dieses Installers läuft bereits."

Function G4wRunOnce
  Push $R0
  StrCpy $R0 "gnupg"
  g4wihelp::runonce
  StrCmp $R0 0 +3
     MessageBox MB_OK $(T_AlreadyRunning)
     Abort
  Pop $R0
FunctionEnd

#
# Control function for the Custom page to select special
# install options.
#
Function CustomPageOptions
  !insertmacro MUI_HEADER_TEXT "$(T_InstallOptions)" "$(T_InstallOptLinks)"

  # Note, that the default selection is done in the ini file
  !insertmacro MUI_INSTALLOPTIONS_WRITE "${W32_SRCDIR}/inst-options.ini" \
	"Field 1" "Text"  "$(T_InstOptLabelA)"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "${W32_SRCDIR}/inst-options.ini" \
	"Field 2" "Text"  "$(T_InstOptFieldA)"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "${W32_SRCDIR}/inst-options.ini" \
	"Field 3" "Text"  "$(T_InstOptFieldB)"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "${W32_SRCDIR}/inst-options.ini" \
	"Field 4" "Text"  "$(T_InstOptFieldC)"
  !insertmacro MUI_INSTALLOPTIONS_WRITE "${W32_SRCDIR}/inst-options.ini" \
	"Field 5" "Text"  "$(T_InstOptLabelB)"

  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "${W32_SRCDIR}/inst-options.ini"
FunctionEnd


# Check whether GnuPG has already been installed.  This is called as
# a leave function from the components page.  A call to abort will get
# back to the components selection.
Function CheckExistingVersion
  ClearErrors
  FileOpen $0 "$INSTDIR\VERSION" r
  IfErrors nexttest
  FileRead $0 $R0
  FileRead $0 $R1
  FileClose $0

  Push $R1
  Call TrimNewLines
  Pop $R1

  MessageBox MB_YESNO "$(T_FoundExistingVersion)" IDYES leave
  Abort

 nexttest:
  ClearErrors
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG" "DisplayVersion"
  IfErrors leave 0
     MessageBox MB_YESNO "$(T_FoundExistingVersionB)" IDYES leave
     Abort

 leave:
FunctionEnd



# PrintNonAdminWarning

# Check whether the current user is in the Administrator group or an
# OS version without the need for an Administrator is in use.  Print a
# diagnostic if this is not the case and abort installation.
Function PrintNonAdminWarning
  ClearErrors
  UserInfo::GetName
  IfErrors leave
  Pop $0
  UserInfo::GetAccountType
  Pop $1
  StrCmp $1 "Admin" leave +1
  MessageBox MB_YESNO "$(T_AdminWanted)" IDNO exit
  goto leave
 exit:
    Quit
 leave:
FunctionEnd


# Check whether the start menu is actually wanted.

Function CheckIfStartMenuWanted
  !insertmacro MUI_INSTALLOPTIONS_READ $R0 "${W32_SRCDIR}/inst-options.ini" \
	"Field 2" "State"
  IntCmp $R0 1 +2
    Abort
FunctionEnd


# Check whether this is a reinstall and popup a message box to explain
# that it is better to close other apps before continuing
Function PrintCloseOtherApps
    IfFileExists $INSTDIR\bin\gpg.exe print_warning
    IfFileExists $INSTDIR\bin\gpa.exe print_warning
    Return
   print_warning:
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(T_CloseOtherApps)"

FunctionEnd

# Called right before the final page to show more warnings.
#Function ShowFinalWarnings
#   leave:
#FunctionEnd

#-----------------------------------------------
# Strings pertaining to the install options page
#-----------------------------------------------

# Installation options title
LangString T_InstallOptions ${LANG_ENGLISH} "Install Options"
LangString T_InstallOptions ${LANG_GERMAN}  "Installationsoptionen"

# Installation options subtitle 1
LangString T_InstallOptLinks ${LANG_ENGLISH} "Start links"
LangString T_InstallOptLinks ${LANG_GERMAN}  "Startlinks"

LangString T_InstOptLabelA  ${LANG_ENGLISH} \
     "Please select where GnuPG shall install links:"
LangString T_InstOptLabelA  ${LANG_GERMAN} \
     "Bitte wählen Sie, welche Verknüpfungen angelegt werden sollen:"

LangString T_InstOptLabelB  ${LANG_ENGLISH} \
     "(Only programs will be linked into the quick launch bar.)"
LangString T_InstOptLabelB  ${LANG_GERMAN} \
     "(In die Schnellstartleiste werden nur Verknüpfungen für \
      Programme angelegt.) "

LangString T_InstOptFieldA  ${LANG_ENGLISH} \
     "Start Menu"
LangString T_InstOptFieldA  ${LANG_GERMAN} \
     "Startmenü"

LangString T_InstOptFieldB  ${LANG_ENGLISH} \
     "Desktop"
LangString T_InstOptFieldB  ${LANG_GERMAN} \
     "Arbeitsfläche"

LangString T_InstOptFieldC  ${LANG_ENGLISH} \
     "Quick Launch Bar"
LangString T_InstOptFieldC  ${LANG_GERMAN} \
     "Schnellstartleiste"

#------------------------------------------------
# String pertaining to the existing version check
#------------------------------------------------
LangString T_FoundExistingVersion ${LANG_ENGLISH} \
     "Version $R1 has already been installed.  $\r$\n\
      Do you want to overwrite it with version ${VERSION}?"
LangString T_FoundExistingVersion ${LANG_GERMAN} \
     "Version $R1 ist hier bereits installiert. $\r$\n\
      Möchten Sie diese mit Version ${VERSION} überschreiben? $\r$\n\
       $\r$\n\
      (Sie können in jedem Fall mit JA antworten, falls es sich um \
       eine neuere oder dieselbe Version handelt.)"
LangString T_FoundExistingVersionB ${LANG_ENGLISH} \
     "A version of GnuPG has already been installed on the system. \
       $\r$\n\
       $\r$\n\
      Do you want to continue installing GnuPG?"
LangString T_FoundExistingVersionB ${LANG_GERMAN} \
     "Eine Version von GnuPG ist hier bereits installiert. \
        $\r$\n\
        $\r$\n\
      Möchten die die Installation von GnuPG fortführen?"



# From Function PrintNonAdminWarning
LangString T_AdminWanted ${LANG_ENGLISH} \
   "Warning: It is recommended to install GnuPG system-wide with \
    administrator rights. \
      $\r$\n\
      $\r$\n\
    Do you want to continue installing GnuPG without administrator rights?"
LangString T_AdminWanted ${LANG_GERMAN} \
   "Achtung: Es wird empfohlen GnuPG systemweit mit \
    Administratorrechten zu installieren. \
      $\r$\n\
      $\r$\n\
    Möchten die die Installation von GnuPG ohne Administratorrechte fortführen?"

# From Function PrintCloseOtherApps
LangString T_CloseOtherApps ${LANG_ENGLISH} \
   "Please make sure that other applications are not running. \
    GnuPG will try to install anyway but a reboot may be required."
LangString T_CloseOtherApps ${LANG_GERMAN} \
   "Bitte stellen Sie sicher, daß alle anderen Anwendugen geschlossen \
    sind.  GnuPG wird auf jeden Fall versuchen, eine Installation \
    durchzuführen; es ist dann aber u.U. notwendig, das System neu zu starten."


# TrimNewlines  - taken from the NSIS reference
# input, top of stack  (e.g. whatever$\r$\n)
# output, top of stack (replaces, with e.g. whatever)
# modifies no other variables.
Function TrimNewlines
   Exch $R0
   Push $R1
   Push $R2
   StrCpy $R1 0

 loop:
   IntOp $R1 $R1 - 1
   StrCpy $R2 $R0 1 $R1
   StrCmp $R2 "$\r" loop
   StrCmp $R2 "$\n" loop
   IntOp $R1 $R1 + 1
   IntCmp $R1 0 no_trim_needed
   StrCpy $R0 $R0 $R1

 no_trim_needed:
   Pop $R2
   Pop $R1
   Exch $R0
FunctionEnd


# AddToPath - Adds the given dir to the search path.
#        Input - head of the stack
Function AddToPath
  ClearErrors
  UserInfo::GetName
  IfErrors add_admin
  Pop $0
  UserInfo::GetAccountType
  Pop $1
  StrCmp $1 "Admin" add_admin add_user

add_admin:
  Exch $0
  g4wihelp::path_add "$0" "0"
  goto add_done
add_user:
  Exch $0
  g4wihelp::path_add "$0" "1"
  goto add_done

add_done:
  StrCmp $R5 "0" add_to_path_done
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  add_to_path_done:
  Pop $0
FunctionEnd


# RemoveFromPath - Remove a given dir from the path
#     Input: head of the stack
Function un.RemoveFromPath
  ClearErrors
  UserInfo::GetName
  IfErrors remove_admin
  Pop $0
  UserInfo::GetAccountType
  Pop $1
  StrCmp $1 "Admin" remove_admin remove_user

remove_admin:
  Exch $0
  g4wihelp::path_remove "$0" "0"
  goto remove_done
remove_user:
  Exch $0
  g4wihelp::path_remove "$0" "1"
  goto remove_done

remove_done:
  StrCmp $R5 "0" remove_from_path_done
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  remove_from_path_done:
  Pop $0
FunctionEnd


#
# Define the installer sections.
#

Section "-gnupginst"
  SetOutPath "$INSTDIR"

  File "${BUILD_DIR}/README.txt"

  # Write a version file.
  FileOpen $0 "$INSTDIR\VERSION" w
  FileWrite $0 "${PACKAGE}$\r$\n"
  FileWrite $0 "${VERSION}$\r$\n"
  FileClose $0

  WriteRegStr SHCTX "Software\GnuPG" "Install Directory" $INSTDIR

  # If we are reinstalling, try to kill a possible running gpa using
  # an already installed gpa.
  ifFileExists "$INSTDIR\bin\launch-gpa.exe"  0 no_uiserver
    nsExec::ExecToLog '"$INSTDIR\bin\launch-gpa" "--stop-server"'

  no_uiserver:

  # If we are reinstalling, try to kill a possible running agent using
  # an already installed gpgconf.

  ifFileExists "$INSTDIR\bin\gpgconf.exe"  0 no_gpgconf
    nsExec::ExecToLog '"$INSTDIR\bin\gpgconf" "--kill" "dirmngr"'
    nsExec::ExecToLog '"$INSTDIR\bin\gpgconf" "--kill" "gpg-agent"'

  no_gpgconf:

  # Add the bin directory to the PATH
  Push "$INSTDIR\bin"
  Call AddToPath
  DetailPrint "Added $INSTDIR\bin to PATH"
SectionEnd

LangString DESC_Menu_gnupg_readme ${LANG_ENGLISH} \
   "General information on GnuPG"
LangString DESC_Menu_gnupg_readme ${LANG_GERMAN} \
   "Allgemeine Informationen zu GnuPG"


Section "GnuPG" SEC_gnupg
  SectionIn RO

  SetOutPath "$INSTDIR\bin"
  File "bin/gpg.exe"
  File "bin/gpgv.exe"
  File "bin/gpgsm.exe"
  File "bin/gpgconf.exe"
  File "bin/gpg-connect-agent.exe"
  File "bin/gpgtar.exe"
  File "libexec/dirmngr_ldap.exe"
  File "libexec/gpg-preset-passphrase.exe"
  File "libexec/gpg-check-pattern.exe"
  File "libexec/gpg-wks-client.exe"

  ClearErrors
  SetOverwrite try
  File "bin/gpg-agent.exe"
  SetOverwrite lastused
  ifErrors 0 +3
      File /oname=gpg-agent.exe.tmp "bin/gpg-agent.exe"
      Rename /REBOOTOK gpg-agent.exe.tmp gpg-agent.exe

  ClearErrors
  SetOverwrite try
  File "bin/dirmngr.exe"
  SetOverwrite lastused
  ifErrors 0 +3
      File /oname=dirmngr.exe.tmp "bin/dirmngr.exe"
      Rename /REBOOTOK dirmngr.exe.tmp dirmngr.exe

  ClearErrors
  SetOverwrite try
  File "libexec/scdaemon.exe"
  SetOverwrite lastused
  ifErrors 0 +3
      File /oname=scdaemon.exe.tmp "libexec/scdaemon.exe"
      Rename /REBOOTOK scdaemon.exe.tmp scdaemon.exe

  SetOutPath "$INSTDIR\share\gnupg"
  File "share/gnupg/distsigkey.gpg"
  File "share/gnupg/sks-keyservers.netCA.pem"

  SetOutPath "$INSTDIR\share\doc\gnupg\examples"
  File "share/doc/gnupg/examples/VS-NfD.prf"
  File "share/doc/gnupg/examples/Automatic.prf"
  File "share/doc/gnupg/examples/pwpattern.list"

  SetOutPath "$INSTDIR\share\locale\ca\LC_MESSAGES"
  File share/locale/ca/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\cs\LC_MESSAGES"
  File share/locale/cs/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\da\LC_MESSAGES"
  File share/locale/da/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\de\LC_MESSAGES"
  File share/locale/de/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\el\LC_MESSAGES"
  File share/locale/el/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\en@boldquot\LC_MESSAGES"
  File share/locale/en@boldquot/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\en@quot\LC_MESSAGES"
  File share/locale/en@quot/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\eo\LC_MESSAGES"
  File share/locale/eo/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\es\LC_MESSAGES"
  File share/locale/es/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\et\LC_MESSAGES"
  File share/locale/et/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\fi\LC_MESSAGES"
  File share/locale/fi/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\fr\LC_MESSAGES"
  File share/locale/fr/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\gl\LC_MESSAGES"
  File share/locale/gl/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\hu\LC_MESSAGES"
  File share/locale/hu/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\id\LC_MESSAGES"
  File share/locale/id/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\it\LC_MESSAGES"
  File share/locale/it/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\ja\LC_MESSAGES"
  File share/locale/ja/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\nb\LC_MESSAGES"
  File share/locale/nb/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\pl\LC_MESSAGES"
  File share/locale/pl/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\pt\LC_MESSAGES"
  File share/locale/pt/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\ro\LC_MESSAGES"
  File share/locale/ro/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\ru\LC_MESSAGES"
  File share/locale/ru/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\sk\LC_MESSAGES"
  File share/locale/sk/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\sv\LC_MESSAGES"
  File share/locale/sv/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\tr\LC_MESSAGES"
  File share/locale/tr/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\uk\LC_MESSAGES"
  File share/locale/uk/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\zh_CN\LC_MESSAGES"
  File share/locale/zh_CN/LC_MESSAGES/gnupg2.mo
  SetOutPath "$INSTDIR\share\locale\zh_TW\LC_MESSAGES"
  File share/locale/zh_TW/LC_MESSAGES/gnupg2.mo
SectionEnd


LangString DESC_SEC_gnupg ${LANG_ENGLISH} \
   "The GnuPG Core is the actual encrypt core and a set of command \
    line utilities."
LangString DESC_SEC_gnupg ${LANG_GERMAN} \
   "Der GnuPG Core ist, wie der Name schon sagt, der Kernbestandteil \
    dieser Software.  Der GnuPG Core stellt die eigentliche \
    Verschlüsselung sowie die Verwaltung der Schlüssel bereit."

LangString DESC_Menu_gnupg_manual ${LANG_ENGLISH} \
   "Show the manual for the GnuPG Core"
LangString DESC_Menu_gnupg_manual ${LANG_GERMAN} \
   "Das Handbuch zum GnuPG Kern anzeigen"

Section "-libgpg-error" SEC_libgpg_error
  SetOutPath "$INSTDIR\bin"
  File bin/libgpg-error-0.dll
  SetOutPath "$INSTDIR\lib"
  File /oname=libgpg-error.imp lib/libgpg-error.dll.a
  SetOutPath "$INSTDIR\include"
  File include/gpg-error.h
  SetOutPath "$INSTDIR\share\locale\cs\LC_MESSAGES"
  File share/locale/cs/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\da\LC_MESSAGES"
  File share/locale/da/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\de\LC_MESSAGES"
  File share/locale/de/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\eo\LC_MESSAGES"
  File share/locale/eo/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\es\LC_MESSAGES"
  File share/locale/es/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\fr\LC_MESSAGES"
  File share/locale/fr/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\hu\LC_MESSAGES"
  File share/locale/hu/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\it\LC_MESSAGES"
  File share/locale/it/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\ja\LC_MESSAGES"
  File share/locale/ja/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\nl\LC_MESSAGES"
  File share/locale/nl/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\pl\LC_MESSAGES"
  File share/locale/pl/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\pt\LC_MESSAGES"
  File share/locale/pt/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\ro\LC_MESSAGES"
  File share/locale/ro/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\ru\LC_MESSAGES"
  File share/locale/ru/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\sr\LC_MESSAGES"
  File share/locale/sr/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\sv\LC_MESSAGES"
  File share/locale/sv/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\uk\LC_MESSAGES"
  File share/locale/uk/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\vi\LC_MESSAGES"
  File share/locale/vi/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\zh_CN\LC_MESSAGES"
  File share/locale/zh_CN/LC_MESSAGES/libgpg-error.mo
  SetOutPath "$INSTDIR\share\locale\zh_TW\LC_MESSAGES"
  File share/locale/zh_TW/LC_MESSAGES/libgpg-error.mo
SectionEnd

Section "-zlib" SEC_zlib
  SetOutPath "$INSTDIR\bin"
  File bin/zlib1.dll
SectionEnd

Section "-npth" SEC_npth
  SetOutPath "$INSTDIR\bin"
  File bin/libnpth-0.dll
  SetOutPath "$INSTDIR\lib"
  File /oname=libnpth.imp lib/libnpth.dll.a
  SetOutPath "$INSTDIR\include"
  File include/npth.h
SectionEnd

Section "-gcrypt" SEC_gcrypt
  SetOutPath "$INSTDIR\bin"
  File bin/libgcrypt-20.dll
  SetOutPath "$INSTDIR\lib"
  File /oname=libgcrypt.imp lib/libgcrypt.dll.a
  SetOutPath "$INSTDIR\include"
  File include/gcrypt.h
SectionEnd

Section "-assuan" SEC_assuan
  SetOutPath "$INSTDIR\bin"
  File bin/libassuan-0.dll
  SetOutPath "$INSTDIR\lib"
  File /oname=libassuan.imp lib/libassuan.dll.a
  SetOutPath "$INSTDIR\include"
  File include/assuan.h
SectionEnd

Section "-ksba" SEC_ksba
  SetOutPath "$INSTDIR\bin"
  File bin/libksba-8.dll
  SetOutPath "$INSTDIR\lib"
  File /oname=libksba.imp lib/libksba.dll.a
  SetOutPath "$INSTDIR\include"
  File include/ksba.h
SectionEnd

Section "-gpgme" SEC_gpgme
  SetOutPath "$INSTDIR\bin"
  File bin/libgpgme-11.dll
  File /nonfatal bin/libgpgme-glib-11.dll
  File libexec/gpgme-w32spawn.exe
  SetOutPath "$INSTDIR\lib"
  File /oname=libgpgme.imp      lib/libgpgme.dll.a
  File /nonfatal /oname=libgpgme-glib.imp lib/libgpgme-glib.dll.a
  SetOutPath "$INSTDIR\include"
  File include/gpgme.h
SectionEnd

Section "-sqlite" SEC_sqlite
  SetOutPath "$INSTDIR\bin"
  File bin/libsqlite3-0.dll
SectionEnd

!ifdef WITH_GUI
Section "-libiconv" SEC_libiconv
  SetOutPath "$INSTDIR\bin"
  File bin/libiconv-2.dll
SectionEnd

Section "-gettext" SEC_gettext
  SetOutPath "$INSTDIR\bin"
  File bin/libintl-8.dll
SectionEnd

Section "-glib" SEC_glib
  SetOutPath "$INSTDIR\bin"
  File bin/libgio-2.0-0.dll
  File bin/libglib-2.0-0.dll
  File bin/libgmodule-2.0-0.dll
  File bin/libgobject-2.0-0.dll
  File bin/libgthread-2.0-0.dll
  File bin/gspawn-win32-helper.exe
  File bin/gspawn-win32-helper-console.exe

  File bin/libffi-6.dll
SectionEnd

Section "-libpng" SEC_libpng
  SetOutPath "$INSTDIR\bin"
  File bin/libpng14-14.dll
SectionEnd

#Section "-jpeg" SEC_jpeg
#  SetOutPath "$INSTDIR"
#  File bin/jpeg62.dll
#SectionEnd

Section "-cairo" SEC_cairo
  SetOutPath "$INSTDIR\bin"
  File bin/libcairo-gobject-2.dll
  File bin/libpangocairo-1.0-0.dll
  File bin/libcairo-2.dll
  File bin/libcairo-script-interpreter-2.dll
SectionEnd

Section "-pixman" SEC_pixman
  SetOutPath "$INSTDIR\bin"
  File bin/libpixman-1-0.dll
SectionEnd

Section "-pango" SEC_pango
  SetOutPath "$INSTDIR\bin"
  File bin/pango-querymodules.exe
  File bin/libpango-1.0-0.dll
  File bin/libpangowin32-1.0-0.dll

  SetOutPath "$INSTDIR\lib\pango\1.6.0\modules"
  File lib/pango/1.6.0/modules/pango-basic-win32.dll
  File lib/pango/1.6.0/modules/pango-arabic-lang.dll
  File lib/pango/1.6.0/modules/pango-indic-lang.dll

  SetOutPath "$INSTDIR\etc\pango"
  File ${W32_SRCDIR}/pango.modules
SectionEnd

Section "-atk" SEC_atk
  SetOutPath "$INSTDIR\bin"
  File bin/libatk-1.0-0.dll
SectionEnd

Section "-gtk+" SEC_gtk_
  SetOutPath "$INSTDIR\bin"
  File bin/libgdk_pixbuf-2.0-0.dll
  File bin/libgdk-win32-2.0-0.dll
  File bin/libgtk-win32-2.0-0.dll

  SetOutPath "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0"
  File /oname=loaders.cache ${W32_SRCDIR}/gdk-pixbuf-loaders.cache
  SetOutPath "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders"
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ani.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gdip-bmp.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gdip-emf.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gdip-gif.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gdip-ico.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gdip-jpeg.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gdip-tiff.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-gdip-wmf.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-icns.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-pcx.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-png.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-pnm.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-qtif.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ras.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-tga.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-wbmp.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-xbm.dll
  File lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-xpm.dll

  SetOutPath "$INSTDIR\lib\gtk-2.0\2.10.0\engines"
  File lib/gtk-2.0/2.10.0/engines/libwimp.dll
  File lib/gtk-2.0/2.10.0/engines/libpixmap.dll

  SetOutPath "$INSTDIR\lib\gtk-2.0\2.10.0\immodules"
  File lib/gtk-2.0/2.10.0/immodules/im-thai.dll
  File lib/gtk-2.0/2.10.0/immodules/im-cyrillic-translit.dll
  File lib/gtk-2.0/2.10.0/immodules/im-multipress.dll
  File lib/gtk-2.0/2.10.0/immodules/im-ti-er.dll
  File lib/gtk-2.0/2.10.0/immodules/im-am-et.dll
  File lib/gtk-2.0/2.10.0/immodules/im-cedilla.dll
  File lib/gtk-2.0/2.10.0/immodules/im-inuktitut.dll
  File lib/gtk-2.0/2.10.0/immodules/im-viqr.dll
  File lib/gtk-2.0/2.10.0/immodules/im-ti-et.dll
  File lib/gtk-2.0/2.10.0/immodules/im-ipa.dll
  File lib/gtk-2.0/2.10.0/immodules/im-ime.dll

  SetOutPath "$INSTDIR\share\themes\Default\gtk-2.0-key"
  File share/themes/Default/gtk-2.0-key/gtkrc

  SetOutPath "$INSTDIR\share\themes\MS-Windows\gtk-2.0"
  File share/themes/MS-Windows/gtk-2.0/gtkrc

  SetOutPath "$INSTDIR\etc\gtk-2.0"
  File etc/gtk-2.0/im-multipress.conf
SectionEnd
!endif

Section "-pinentry" SEC_pinentry
  SetOutPath "$INSTDIR\bin"
  File /oname=pinentry-basic.exe "bin/pinentry-w32.exe"
SectionEnd

!ifdef WITH_GUI
Section "gpa" SEC_gpa
  SectionIn RO
  SetOutPath "$INSTDIR\bin"
  File bin/gpa.exe
  File bin/launch-gpa.exe
SectionEnd

LangString DESC_SEC_gpa ${LANG_ENGLISH} \
   "The GnuPG Assistant is the graphical interface of GnuPG"
LangString DESC_SEC_gpa ${LANG_GERMAN} \
   "Der GnuPG Assistent ist die graphische Oberfläche von GnuPG."

LangString DESC_Menu_gpa ${LANG_ENGLISH} \
   "Run the GnuGP Assistant."
LangString DESC_Menu_gpa ${LANG_GERMAN} \
   "Den GnuPG Assistenten starten."

Section "gpgex" SEC_gpgex
  SetOutPath "$INSTDIR\bin"

  ClearErrors
  SetOverwrite try
  File bin/gpgex.dll
  SetOverwrite lastused
  ifErrors 0 do_reg
      File /oname=gpgex.dll.tmp bin/gpgex.dll
      Rename /REBOOTOK gpgex.dll.tmp gpgex.dll

 do_reg:
  ClearErrors
  RegDLL "$INSTDIR\bin\gpgex.dll"
  ifErrors 0 +2
     MessageBox MB_OK "$(T_GPGEX_RegFailed)"

${If} ${RunningX64}
  # Install the 64 bit version of the plugin.
  # Note that we install this in addition to the 32 bit version so that
  # the 32 bit version can be used by file dialogs of 32 bit programs.
  ClearErrors
  SetOverwrite try
  File /oname=gpgex6.dll "${INST6_DIR}/bin/gpgex.dll"
  SetOverwrite lastused
  ifErrors 0 do_reg64
      File /oname=gpgex6.dll.tmp "${INST6_DIR}/bin/gpgex.dll"
      Rename /REBOOTOK gpgex6.dll.tmp gpgex6.dll

 do_reg64:
  # Register the DLL. We need to register both versions.  However
  # RegDLL can't be used for 64 bit and InstallLib seems to be a
  # registry hack.
  ClearErrors
  nsExec::ExecToLog '"$SYSDIR\regsvr32" "/s" "$INSTDIR\bin\gpgex6.dll"'
  ifErrors 0 +2
     MessageBox MB_OK "$(T_GPGEX_RegFailed) (64 bit)"

  # Note: There is no need to install the help an mo files because
  # they are identical to those installed by the 32 bit version.
${EndIf}
SectionEnd

LangString T_GPGEX_RegFailed ${LANG_ENGLISH} \
   "Warning: Registration of the Explorer plugin failed."

LangString DESC_SEC_gpgex ${LANG_ENGLISH} \
   "GnuPG Explorer Extension"

!endif


Section "-gnupglast" SEC_gnupglast
  SetOutPath "$INSTDIR"
SectionEnd


#
# Define the uninstaller sections.
#
# (reverse order of the installer sections!)
#

Section "-un.gnupglast"
  ifFileExists "$INSTDIR\bin\launch-gpa.exe"  0 no_uiserver
    nsExec::ExecToLog '"$INSTDIR\bin\launch-gpa" "--stop-server"'
  no_uiserver:
  ifFileExists "$INSTDIR\bin\gpgconf.exe"  0 no_gpgconf
    nsExec::ExecToLog '"$INSTDIR\bin\gpgconf" "--kill" "gpg-agent"'
    nsExec::ExecToLog '"$INSTDIR\bin\gpgconf" "--kill" "dirmngr"'
  no_gpgconf:
SectionEnd

Section "-un.gpgex"
  UnRegDLL "$INSTDIR\bin\gpgex.dll"

  Delete /REBOOTOK "$INSTDIR\bin\gpgex.dll"

${If} ${RunningX64}
  nsExec::ExecToLog '"$SYSDIR\regsvr32" "/u" "/s" "$INSTDIR\bin\gpgex6.dll"'
  Delete /REBOOTOK "$INSTDIR\bin\gpgex6.dll"
${EndIf}
SectionEnd

!ifdef WITH_GUI
Section "-un.gpa"
  Delete "$INSTDIR\bin\gpa.exe"
  Delete "$INSTDIR\bin\launch-gpa.exe"

  RMDir "$INSTDIR\share\gpa"
SectionEnd
!endif

Section "-un.pinentry"
  Delete "$INSTDIR\bin\pinentry-basic.exe"
SectionEnd

!ifdef WITH_GUI
Section "-un.gtk+"
  Delete "$INSTDIR\bin\libgdk_pixbuf-2.0-0.dll"
  Delete "$INSTDIR\bin\libgdk-win32-2.0-0.dll"
  Delete "$INSTDIR\bin\libgtk-win32-2.0-0.dll"

  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders.cache"

  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-ani.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-gdip-bmp.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-gdip-emf.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-gdip-gif.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-gdip-ico.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-gdip-jpeg.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-gdip-tiff.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-gdip-wmf.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-icns.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-pcx.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-png.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-pnm.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-qtif.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-ras.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-tga.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-wbmp.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-xbm.dll"
  Delete "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders\libpixbufloader-xpm.dll"
  RMDir  "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0\loaders"
  RMDir  "$INSTDIR\lib\gdk-pixbuf-2.0\2.10.0"
  RMDir  "$INSTDIR\lib\gdk-pixbuf-2.0"

  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\engines\libwimp.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\engines\libpixmap.dll"
  RMDir  "$INSTDIR\lib\gtk-2.0\2.10.0\engines"

  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-thai.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-cyrillic-translit.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-multipress.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-ti-er.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-am-et.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-cedilla.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-inuktitut.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-viqr.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-ti-et.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-ipa.dll"
  Delete "$INSTDIR\lib\gtk-2.0\2.10.0\immodules\im-ime.dll"
  RMDir  "$INSTDIR\lib\gtk-2.0\2.10.0\immodules"

  RMDir  "$INSTDIR\lib\gtk-2.0\2.10.0"
  RMDir  "$INSTDIR\lib\gtk-2.0"

  Delete "$INSTDIR\share\themes\Default\gtk-2.0-key\gtkrc"
  RMDir  "$INSTDIR\share\themes\Default\gtk-2.0-key"
  RMDir  "$INSTDIR\share\themes\Default"

  Delete "$INSTDIR\share\themes\MS-Windows\gtk-2.0\gtkrc"
  RMDir  "$INSTDIR\share\themes\MS-Windows\gtk-2.0"
  RMDir  "$INSTDIR\share\themes\MS-Windows"

  RMDir  "$INSTDIR\share\themes"

  Delete "$INSTDIR\etc\gtk-2.0\im-multipress.conf"
  RMDir  "$INSTDIR\etc\gtk-2.0"
SectionEnd

Section "-un.atk"
  Delete "$INSTDIR\bin\libatk-1.0-0.dll"
SectionEnd

Section "-un.pango"
  Delete "$INSTDIR\bin\pango-querymodules.exe"
  Delete "$INSTDIR\bin\libpango-1.0-0.dll"
  Delete "$INSTDIR\bin\libpangowin32-1.0-0.dll"

  Delete "$INSTDIR\lib\pango\1.6.0\modules\pango-basic-win32.dll"
  Delete "$INSTDIR\lib\pango\1.6.0\modules\pango-arabic-lang.dll"
  Delete "$INSTDIR\lib\pango\1.6.0\modules\pango-indic-lang.dll"
  RMDir  "$INSTDIR\lib\pango\1.6.0\modules"
  RMDir  "$INSTDIR\lib\pango\1.6.0"
  RMDir  "$INSTDIR\lib\pango"

  Delete "$INSTDIR\etc\pango\pango.modules"
  RMDir  "$INSTDIR\etc\pango"
SectionEnd

Section "-un.pixman"
  Delete "$INSTDIR\bin\libpixman-1-0.dll"
SectionEnd

Section "-un.cairo"
  Delete "$INSTDIR\bin\libcairo-gobject-2.dll"
  Delete "$INSTDIR\bin\libpangocairo-1.0-0.dll"
  Delete "$INSTDIR\bin\libcairo-2.dll"
  Delete "$INSTDIR\bin\libcairo-script-interpreter-2.dll"
SectionEnd

Section "-un.libpng"
  Delete "$INSTDIR\bin\libpng14-14.dll"
SectionEnd

Section "-un.glib"
  Delete "$INSTDIR\bin\libgio-2.0-0.dll"
  Delete "$INSTDIR\bin\libglib-2.0-0.dll"
  Delete "$INSTDIR\bin\libgmodule-2.0-0.dll"
  Delete "$INSTDIR\bin\libgobject-2.0-0.dll"
  Delete "$INSTDIR\bin\libgthread-2.0-0.dll"
  Delete "$INSTDIR\bin\gspawn-win32-helper.exe"
  Delete "$INSTDIR\bin\gspawn-win32-helper-console.exe"
  Delete "$INSTDIR\bin\libffi-6.dll"
SectionEnd
!endif


Section "-un.gettext"
  Delete "$INSTDIR\bin\libintl-8.dll"
SectionEnd

Section "-un.libiconv"
  Delete "$INSTDIR\bin\libiconv-2.dll"
SectionEnd

Section "-un.gpgme"
  Delete "$INSTDIR\bin\libgpgme-11.dll"
  Delete "$INSTDIR\bin\libgpgme-glib-11.dll"
  Delete "$INSTDIR\bin\gpgme-w32spawn.exe"
  Delete "$INSTDIR\lib\libgpgme.imp"
  Delete "$INSTDIR\lib\libgpgme-glib.imp"
  Delete "$INSTDIR\include\gpgme.h"
SectionEnd

Section "-un.ksba"
  Delete "$INSTDIR\bin\libksba-8.dll"
  Delete "$INSTDIR\lib\libksba.imp"
  Delete "$INSTDIR\include\ksba.h"
SectionEnd

Section "-un.assuan"
  Delete "$INSTDIR\bin\libassuan-0.dll"
  Delete "$INSTDIR\lib\libassuan.imp"
  Delete "$INSTDIR\include\assuan.h"
SectionEnd

Section "-un.gcrypt"
  Delete "$INSTDIR\bin\libgcrypt-20.dll"
  Delete "$INSTDIR\lib\libgcrypt.imp"
  Delete "$INSTDIR\include\gcrypt.h"
SectionEnd

Section "-un.npth"
  Delete "$INSTDIR\bin\libnpth-0.dll"
  Delete "$INSTDIR\lib\libnpth.imp"
  Delete "$INSTDIR\include\npth.h"
SectionEnd

Section "-un.zlib"
  Delete "$INSTDIR\bin\zlib1.dll"
SectionEnd

Section "-un.libgpg-error"
  Delete "$INSTDIR\bin\libgpg-error-0.dll"
  Delete "$INSTDIR\lib\libgpg-error.imp"
  Delete "$INSTDIR\include\gpg-error.h"
  Delete "$INSTDIR\share\locale\cs\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\cs\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\cs"
  Delete "$INSTDIR\share\locale\da\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\da\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\da"
  Delete "$INSTDIR\share\locale\de\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\de\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\de"
  Delete "$INSTDIR\share\locale\eo\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\eo\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\eo"
  Delete "$INSTDIR\share\locale\es\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\es\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\es"
  Delete "$INSTDIR\share\locale\fr\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\fr\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\fr"
  Delete "$INSTDIR\share\locale\hu\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\hu\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\hu"
  Delete "$INSTDIR\share\locale\it\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\it\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\it"
  Delete "$INSTDIR\share\locale\ja\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\ja\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\ja"
  Delete "$INSTDIR\share\locale\nl\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\nl\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\nl"
  Delete "$INSTDIR\share\locale\pl\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\pl\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\pl"
  Delete "$INSTDIR\share\locale\pt\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\pt\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\pt"
  Delete "$INSTDIR\share\locale\ro\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\ro\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\ro"
  Delete "$INSTDIR\share\locale\ru\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\ru\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\ru"
  Delete "$INSTDIR\share\locale\sr\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\sr\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\sr"
  Delete "$INSTDIR\share\locale\sv\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\sv\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\sv"
  Delete "$INSTDIR\share\locale\uk\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\uk\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\uk"
  Delete "$INSTDIR\share\locale\vi\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\vi\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\vi"
  Delete "$INSTDIR\share\locale\zh_CN\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\zh_CN\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\zh_CN"
  Delete "$INSTDIR\share\locale\zh_TW\LC_MESSAGES\libgpg-error.mo"
  RMDir "$INSTDIR\share\locale\zh_TW\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\zh_TW"
  RMDir "$INSTDIR\share\locale"
SectionEnd

Section "-un.gnupg"
  Delete "$INSTDIR\bin\gpg.exe"
  Delete "$INSTDIR\bin\gpgv.exe"
  Delete "$INSTDIR\bin\gpgsm.exe"
  Delete "$INSTDIR\bin\gpg-agent.exe"
  Delete "$INSTDIR\bin\scdaemon.exe"
  Delete "$INSTDIR\bin\dirmngr.exe"
  Delete "$INSTDIR\bin\gpgconf.exe"
  Delete "$INSTDIR\bin\gpg-connect-agent.exe"
  Delete "$INSTDIR\bin\gpgtar.exe"
  Delete "$INSTDIR\bin\dirmngr_ldap.exe"
  Delete "$INSTDIR\bin\gpg-preset-passphrase.exe"
  Delete "$INSTDIR\bin\gpg-check-pattern.exe"
  Delete "$INSTDIR\bin\gpg-wks-client.exe"

  Delete "$INSTDIR\share\doc\gnupg\examples\VS-NfD.prf"
  Delete "$INSTDIR\share\doc\gnupg\examples\Automatic.prf"
  Delete "$INSTDIR\share\doc\gnupg\examples\pwpattern.list"
  RMDir  "$INSTDIR\share\doc\gnupg\examples"

  Delete "$INSTDIR\share\gnupg\sks-keyservers.netCA.pem"
  Delete "$INSTDIR\share\gnupg\dirmngr-conf.skel"
  Delete "$INSTDIR\share\gnupg\distsigkey.gpg"
  Delete "$INSTDIR\share\gnupg\gpg-conf.skel"
  RMDir  "$INSTDIR\share\gnupg"

  Delete "$INSTDIR\share\locale\ca\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\ca\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\ca"
  Delete "$INSTDIR\share\locale\cs\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\cs\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\cs"
  Delete "$INSTDIR\share\locale\da\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\da\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\da"
  Delete "$INSTDIR\share\locale\de\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\de\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\de"
  Delete "$INSTDIR\share\locale\el\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\el\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\el"
  Delete "$INSTDIR\share\locale\en@boldquot\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\en@boldquot\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\en@boldquot"
  Delete "$INSTDIR\share\locale\en@quot\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\en@quot\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\en@quot"
  Delete "$INSTDIR\share\locale\eo\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\eo\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\eo"
  Delete "$INSTDIR\share\locale\es\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\es\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\es"
  Delete "$INSTDIR\share\locale\et\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\et\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\et"
  Delete "$INSTDIR\share\locale\fi\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\fi\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\fi"
  Delete "$INSTDIR\share\locale\fr\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\fr\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\fr"
  Delete "$INSTDIR\share\locale\gl\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\gl\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\gl"
  Delete "$INSTDIR\share\locale\hu\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\hu\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\hu"
  Delete "$INSTDIR\share\locale\id\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\id\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\id"
  Delete "$INSTDIR\share\locale\it\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\it\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\it"
  Delete "$INSTDIR\share\locale\ja\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\ja\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\ja"
  Delete "$INSTDIR\share\locale\nb\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\nb\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\nb"
  Delete "$INSTDIR\share\locale\pl\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\pl\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\pl"
  Delete "$INSTDIR\share\locale\pt\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\pt\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\pt"
  Delete "$INSTDIR\share\locale\ro\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\ro\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\ro"
  Delete "$INSTDIR\share\locale\ru\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\ru\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\ru"
  Delete "$INSTDIR\share\locale\sk\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\sk\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\sk"
  Delete "$INSTDIR\share\locale\sv\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\sv\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\sv"
  Delete "$INSTDIR\share\locale\tr\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\tr\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\tr"
  Delete "$INSTDIR\share\locale\uk\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\uk\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\uk"
  Delete "$INSTDIR\share\locale\zh_CN\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\zh_CN\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\zh_CN"
  Delete "$INSTDIR\share\locale\zh_TW\LC_MESSAGES\gnupg2.mo"
  RMDir "$INSTDIR\share\locale\zh_TW\LC_MESSAGES"
  RMDir "$INSTDIR\share\locale\zh_TW"
  RMDir "$INSTDIR\share\locale"
SectionEnd

Section "-un.sqlite"
  Delete "$INSTDIR\bin\libsqlite3-0.dll"
SectionEnd

Section "-un.gnupginst"
  # Delete standard stuff.
  Delete "$INSTDIR\README.txt"

  Delete "$INSTDIR\VERSION"

  # Remove the bin directory from the PATH
  Push "$INSTDIR\bin"
  Call un.RemoveFromPath

  # Try to remove the top level directories.
  RMDir "$INSTDIR\bin"
  RMDir "$INSTDIR\lib"
  RMDir "$INSTDIR\include"
  RMDir "$INSTDIR\share"
  RMDir "$INSTDIR\etc"
  RMDir "$INSTDIR"

  # Clean the registry.
  DeleteRegValue SHCTX "Software\GNU\GnuPG" "Install Directory"
SectionEnd


Function .onInit
  ;;!define MUI_LANGDLL_ALWAYSSHOW
  !insertmacro MUI_LANGDLL_DISPLAY

  Call G4wRunOnce

  SetOutPath $TEMP
#!ifdef SOURCES
#  File /oname=gpgspltmp.bmp "${TOP_SRCDIR}/doc/logo/gnupg-logo-400px.bmp"
#  # We play the tune only for the soruce installer
#  File /oname=gpgspltmp.wav "${TOP_SRCDIR}/src/gnupg-splash.wav"
#  g4wihelp::playsound $TEMP\gpgspltmp.wav
#  g4wihelp::showsplash 2500 $TEMP\gpgspltmp.bmp

#  Delete $TEMP\gpgspltmp.bmp
#  # Note that we delete gpgspltmp.wav in .onInst{Failed,Success}
#!endif

  # We can't use TOP_SRCDIR dir as the name of the file needs to be
  # the same while building and running the installer.  Thus we
  # generate the file from a template.
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "${W32_SRCDIR}/inst-options.ini"

  #Call CalcDepends

  Var /GLOBAL changed_dir
  # Check if the install directory was modified on the command line
  StrCmp "$INSTDIR" "$PROGRAMFILES\${INSTALL_DIR}" unmodified 0
  # It is modified. Save that value.
  StrCpy $changed_dir "$INSTDIR"

  # MULITUSER_INIT overwrites directory setting from command line
  !insertmacro MULTIUSER_INIT
  StrCpy $INSTDIR "$changed_dir"
  goto initDone
unmodified:
  !insertmacro MULTIUSER_INIT
initDone:
FunctionEnd

Function "un.onInit"
  !insertmacro MULTIUSER_UNINIT
FunctionEnd

#Function .onInstFailed
#  Delete $TEMP\gpgspltmp.wav
#FunctionEnd

#Function .onInstSuccess
#  Delete $TEMP\gpgspltmp.wav
#FunctionEnd

#Function .onSelChange
#  Call CalcDepends
#FunctionEnd


# This must be in a central place.  Urgs.

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_gnupg} $(DESC_SEC_gnupg)
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_gpa}   $(DESC_SEC_gpa)
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_gpgex} $(DESC_SEC_gpgex)
!insertmacro MUI_FUNCTION_DESCRIPTION_END


# This also must be in a central place.  Also Urgs.

!ifdef WITH_GUI
Section "-startmenu"

  # Check if the start menu entries where requested.
  !insertmacro MUI_INSTALLOPTIONS_READ $R0 "${W32_SRCDIR}/inst-options.ini" \
	"Field 2" "State"
  IntCmp $R0 0 no_start_menu

!insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    CreateDirectory "$SMPROGRAMS\$STARTMENU_FOLDER"

    SectionGetFlags ${SEC_gpa} $R0
    IntOp $R0 $R0 & ${SF_SELECTED}
    IntCmp $R0 ${SF_SELECTED} 0 no_gpa_menu
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\GPA.lnk" \
	"$INSTDIR\bin\launch-gpa.exe" \
        "" "" "" SW_SHOWNORMAL "" $(DESC_Menu_gpa)
  no_gpa_menu:


    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\GnuPG Manual.lnk" \
                   "$INSTDIR\share\gnupg\gnupg.html" \
                   "" "" "" SW_SHOWNORMAL "" $(DESC_Menu_gnupg_manual)

    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\GnuPG README.lnk" \
                   "$INSTDIR\README.txt" \
                   "" "" "" SW_SHOWNORMAL "" $(DESC_Menu_gnupg_readme)

!insertmacro MUI_STARTMENU_WRITE_END



no_start_menu:


  # Check if the desktop entries where requested.
  !insertmacro MUI_INSTALLOPTIONS_READ $R0 "${W32_SRCDIR}/inst-options.ini" \
	"Field 3" "State"
  IntCmp $R0 0 no_desktop

    SectionGetFlags ${SEC_gpa} $R0
    IntOp $R0 $R0 & ${SF_SELECTED}
    IntCmp $R0 ${SF_SELECTED} 0 no_gpa_desktop
    CreateShortCut "$DESKTOP\GPA.lnk" \
	"$INSTDIR\bin\launch-gpa.exe" \
        "" "" "" SW_SHOWNORMAL "" $(DESC_Menu_gpa)
  no_gpa_desktop:


    CreateShortCut "$DESKTOP\GPA Manual.lnk" \
                   "$INSTDIR\share\gpa\gpa.html" \
                   "" "" "" SW_SHOWNORMAL "" $(DESC_Menu_gpa_manual)

no_desktop:


  # Check if the quick launch bar entries where requested.
  !insertmacro MUI_INSTALLOPTIONS_READ $R0 "${W32_SRCDIR}/inst-options.ini" \
	"Field 4" "State"
  IntCmp $R0 0 no_quick_launch
  StrCmp $QUICKLAUNCH $TEMP no_quick_launch

    SectionGetFlags ${SEC_gpa} $R0
    IntOp $R0 $R0 & ${SF_SELECTED}
    IntCmp $R0 ${SF_SELECTED} 0 no_gpa_quicklaunch
    CreateShortCut "$QUICKLAUNCH\GPA.lnk" \
	"$INSTDIR\bin\launch-gpa.exe" \
        "" "" "" SW_SHOWNORMAL "" $(DESC_Menu_gpa)
no_gpa_quicklaunch:


no_quick_launch:


SectionEnd
!endif


#
# Now for the generic parts to end the installation.
#
Var MYTMP

# Last section is a hidden one.
Section
  WriteUninstaller "$INSTDIR\gnupg-uninstall.exe"

  # Windows Add/Remove Programs support
  StrCpy $MYTMP "Software\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG"
  WriteRegExpandStr SHCTX $MYTMP "UninstallString" '"$INSTDIR\gnupg-uninstall.exe"'
  WriteRegExpandStr SHCTX $MYTMP "InstallLocation" "$INSTDIR"
  WriteRegStr       SHCTX $MYTMP "DisplayName"     "${PRETTY_PACKAGE}"
!ifdef WITH_GUI
  WriteRegStr       SHCTX $MYTMP "DisplayIcon"     "$INSTDIR\bin\gpa.exe,0"
!else
  WriteRegStr       SHCTX $MYTMP "DisplayIcon"     "$INSTDIR\bin\gpg.exe,0"
!endif
  WriteRegStr       SHCTX $MYTMP "DisplayVersion"  "${VERSION}"
  WriteRegStr       SHCTX $MYTMP "Publisher"       "The GnuPG Project"
  WriteRegStr       SHCTX $MYTMP "URLInfoAbout"    "https://gnupg.org"
  WriteRegDWORD     SHCTX $MYTMP "NoModify"        "1"
  WriteRegDWORD     SHCTX $MYTMP "NoRepair"        "1"
SectionEnd

Section Uninstall
!ifdef WITH_GUI
  #---------------------------------------------------
  # Delete the menu entries and any empty parent menus
  #---------------------------------------------------
  !insertmacro MUI_STARTMENU_GETFOLDER Application $MYTMP
  Delete "$SMPROGRAMS\$MYTMP\GPA.lnk"
  Delete "$SMPROGRAMS\$MYTMP\GnuPG Manual.lnk"
  Delete "$SMPROGRAMS\$MYTMP\GnuPG README.lnk"
  Delete "$SMPROGRAMS\$MYTMP\*.lnk"
  StrCpy $MYTMP "$SMPROGRAMS\$MYTMP"
  startMenuDeleteLoop:
    ClearErrors
    RMDir $MYTMP
    GetFullPathName $MYTMP "$MYTMP\.."
    IfErrors startMenuDeleteLoopDone
    StrCmp $MYTMP $SMPROGRAMS startMenuDeleteLoopDone startMenuDeleteLoop
  startMenuDeleteLoopDone:

  DeleteRegValue SHCTX "Software\GNU\GnuPG" "Start Menu Folder"

  # Delete Desktop links.
  Delete "$DESKTOP\GPA.lnk"
  Delete "$DESKTOP\GnuPG Manual.lnk"
  Delete "$DESKTOP\GnuPG README.lnk"

  # Delete Quick Launch Bar links.
  StrCmp $QUICKLAUNCH $TEMP no_quick_launch_uninstall
  Delete "$QUICKLAUNCH\GPA.lnk"
no_quick_launch_uninstall:

!endif

  Delete "$INSTDIR\gnupg-uninstall.exe"
  RMDir "$INSTDIR"

  # Clean the registry.
  DeleteRegValue SHCTX "Software\GnuPG" "Install Directory"
  DeleteRegKey /ifempty SHCTX "Software\GnuPG"
  # Remove Windows Add/Remove Programs support.
  DeleteRegKey SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG"
SectionEnd
