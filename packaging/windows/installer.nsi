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
!include "Sections.nsh"
!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_WELCOMEPAGE_TEXT "This installs ${APPNAME} ${VERSION}, which finds and diagnoses Ubiquiti and other WISP gear on your network.$\r$\n$\r$\nNo administrator rights are needed. The first time it scans, Windows Firewall may ask about Python: allow it on private networks so devices' replies get through."
!define MUI_FINISHPAGE_RUN "${LAUNCHER}"
!define MUI_FINISHPAGE_RUN_PARAMETERS "${LAUNCHARGS}"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APPNAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "${APPNAME}" SecApp
  SectionIn RO
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

; Npcap's license doesn't allow bundling it, so this fetches the official installer from npcap.com,
; checks it's signed by the Nmap Project, and starts it for you to click through (it asks for
; administrator rights itself). Ticked when Npcap isn't installed yet, like Wireshark does.
Section /o "Npcap (packet capture for Sniff, Trunk VLANs and Direct)" SecNpcap
  DetailPrint "Getting Npcap from npcap.com..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\app\opendisco\resources\get-npcap.ps1"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Npcap wasn't installed (no internet, or its installer was cancelled). \
      The app offers it again the first time you sniff, or get it from npcap.com."
  ${EndIf}
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecApp} "The app, with its own copy of Python."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecNpcap} "Downloads Npcap from npcap.com and starts its installer. Needed only \
    for capturing packets: Sniff the wire, Trunk VLANs and Direct to a device. Free for up to 5 computers."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function .onInit
  ; A 32-bit installer sees the real System32 as Sysnative.
  ${IfNot} ${FileExists} "$WINDIR\Sysnative\Npcap\wpcap.dll"
  ${AndIfNot} ${FileExists} "$WINDIR\System32\Npcap\wpcap.dll"
    !insertmacro SelectSection ${SecNpcap}
  ${EndIf}
FunctionEnd

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
