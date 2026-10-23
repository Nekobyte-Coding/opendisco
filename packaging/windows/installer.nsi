; OpenDisco installer for Windows. Built by build_installer.py, which passes
; VERSION, VERSION_NUMERIC, STAGE (the files to install), OUTFILE and ICON.
;
; Installs per user into %LOCALAPPDATA%\Programs, so it needs no administrator rights.

Unicode true
!define APPNAME "OpenDisco"
!define OLDNAME "OpenDisco"  ; its name until 1.3.1
!define PUBLISHER "Michael Froehlke"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
!define LAUNCHER "$INSTDIR\python\pythonw.exe"
!define LAUNCHARGS "-m opendisco"
!define APPICON "$INSTDIR\app\opendisco\resources\icon.ico"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\${APPNAME}"
InstallDirRegKey HKCU "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
ShowInstDetails nevershow

VIProductVersion "${VERSION_NUMERIC}"
VIAddVersionKey "ProductName" "${APPNAME}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${APPNAME} installer"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 ${PUBLISHER}"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_WELCOMEPAGE_TEXT "This installs ${APPNAME} ${VERSION}, which finds and diagnoses Ubiquiti and other WISP gear on your network.$\r$\n$\r$\nNo administrator rights are needed. The first time it scans, Windows Firewall may ask about Python: allow it on private networks so devices' replies get through."
!define MUI_FINISHPAGE_RUN "${LAUNCHER}"
!define MUI_FINISHPAGE_RUN_PARAMETERS "${LAUNCHARGS}"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APPNAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  ; Until 1.3.1 the app was called OpenDisco: remove that install so there's only one. Its
  ; uninstaller leaves your data, which the app copies to its new folder the first time it runs.
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${OLDNAME}" "UninstallString"
  ReadRegStr $1 HKCU "Software\${OLDNAME}" "InstallDir"
  ${If} $0 != ""
  ${AndIf} $1 != ""
    ExecWait '$0 /S _?=$1'
    Delete "$1\Uninstall.exe"
    RMDir "$1"
  ${EndIf}
  ; An upgrade replaces the bundled Python and app, so no stale files are left behind.
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\app"
  SetOutPath "$INSTDIR"
  File /r "${STAGE}/*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Shortcuts start in the install folder.
  SetOutPath "$INSTDIR"
  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "${LAUNCHER}" "${LAUNCHARGS}" "${APPICON}" 0
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "${LAUNCHER}" "${LAUNCHARGS}" "${APPICON}" 0

  WriteRegStr HKCU "Software\${APPNAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTKEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayIcon" "${APPICON}"
  WriteRegStr HKCU "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  Delete "$DESKTOP\${APPNAME}.lnk"
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\app"
  Delete "$INSTDIR\opendisco.cmd"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTKEY}"
  DeleteRegKey HKCU "Software\${APPNAME}"
  ; The networks file and settings in %LOCALAPPDATA% are left alone, like most apps do.
SectionEnd
