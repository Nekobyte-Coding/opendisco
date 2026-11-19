; OpenDisco (Open Discovery Tool for Ubiquiti Devices) installer for Windows. Built by
; build_installer.py, which passes VERSION, VERSION_NUMERIC, STAGE (the files to install), OUTFILE
; and ICON.
;
; Installs per user into %LOCALAPPDATA%\Programs, so it needs no administrator rights.

Unicode true
!define APPNAME "OpenDisco"
!define FULLNAME "Open Discovery Tool for Ubiquiti Devices"
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
VIAddVersionKey "LegalCopyright" "Copyright 2026 ${PUBLISHER}. Apache License 2.0"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "Sections.nsh"
!include "FileFunc.nsh"
!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_WELCOMEPAGE_TEXT "This installs ${APPNAME} ${VERSION}, the ${FULLNAME}, which finds and diagnoses Ubiquiti and other WISP gear.$\r$\n$\r$\nNo administrator rights are needed. The first time it scans, Windows Firewall may ask about Python: allow it on private networks so devices' replies get through."
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

; Versions before 1.4.0 installed under the app's earlier names: remove such an install so there's
; only one. Its uninstaller leaves the saved data, which the app copies over the first time it runs.
!macro RemoveEarlierInstall NAME
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${NAME}" "UninstallString"
  ReadRegStr $1 HKCU "Software\${NAME}" "InstallDir"
  ${If} $0 != ""
  ${AndIf} $1 != ""
    ExecWait '$0 /S _?=$1'
    ; Windows (Defender's scan) can hold the finished uninstaller for a moment: retry for 5s.
    StrCpy $2 0
    ${Do}
      Delete "$1\Uninstall.exe"
      ${IfNot} ${FileExists} "$1\Uninstall.exe"
        ${Break}
      ${EndIf}
      Sleep 250
      IntOp $2 $2 + 1
    ${LoopUntil} $2 >= 20
    RMDir "$1"
  ${EndIf}
!macroend

; A running OpenDisco (pythonw.exe from the Start menu, python.exe from opendisco.cmd, under
; $INSTDIR) holds its files open, so copying over or removing them fails ("Error opening file for
; writing"). This closes it first: it asks (a silent install, how the app updates itself, says OK),
; then stops every process run from $INSTDIR except this installer itself (an uninstaller run with
; _?= runs from there). update-windows.ps1 runs setup.exe from %TEMP% after the app has quit, so the
; update is never in the way. If PowerShell can't check, it asks the user to close OpenDisco.
!define FIND_RUNNING "$$d = $$env:OPENDISCO_DIR.TrimEnd('\') + '\'; \
  $$me = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $$PID)).ParentProcessId; \
  $$p = @(Get-Process | Where-Object { $$_.Path -and $$_.Id -ne $$me -and \
  $$_.Path.StartsWith($$d, [StringComparison]::OrdinalIgnoreCase) });"
; setup.exe is 32-bit, so a plain "powershell" is the 32-bit one (SysWOW64), and there Get-Process
; can't read the Path of the app's 64-bit pythonw.exe. Sysnative is the native System32 as a 32-bit
; process sees it (absent on 32-bit Windows).
; The answer comes back as the exit code, 10 + how many are running: nsExec reads a short output
; like "1<CR><LF>" as UTF-16 (one character, U+0D31), so 1.8.1 always read 0 there. Any other exit
; code (or "error") means PowerShell couldn't check.
Var PowerShell
!define POWERSHELL "$PowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command"
!macro CloseRunningApp UN
Function ${UN}CloseRunningApp
  ; The folder goes to PowerShell in an environment variable: no quoting to get wrong.
  System::Call 'kernel32::SetEnvironmentVariable(t "OPENDISCO_DIR", t "$INSTDIR")'
  StrCpy $PowerShell "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
  ${If} ${FileExists} "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    StrCpy $PowerShell "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
  ${EndIf}
  StrCpy $PowerShell `"$PowerShell"`
  nsExec::ExecToStack `${POWERSHELL} "${FIND_RUNNING} exit 10 + $$p.Count"`
  Pop $0  ; exit code: 10 + how many are running, or "error"
  Pop $1  ; output (unused)
  ${If} $0 == 10
    Return
  ${ElseIf} $0 < 10  ; also "error", which reads as 0
    Goto unchecked
  ${EndIf}
  MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "${APPNAME} is running. Click OK to close it and continue, \
    or Cancel to stop." /SD IDOK IDOK close
  SetErrorLevel 2
  Abort
  close:
    DetailPrint "Closing ${APPNAME}..."
    nsExec::ExecToStack `${POWERSHELL} "${FIND_RUNNING} $$p | Stop-Process -Force -ErrorAction SilentlyContinue; \
      $$p | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue; ${FIND_RUNNING} exit 10 + $$p.Count"`
    Pop $0
    Pop $1
    ${If} $0 == 10
      Return
    ${ElseIf} $0 < 10
      Goto unchecked
    ${EndIf}
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Couldn't close ${APPNAME}. Close it yourself (check Task \
      Manager), then click Retry." /SD IDCANCEL IDRETRY close
    SetErrorLevel 2
    Abort
  unchecked:
    ; PowerShell couldn't check (or close): never carry on silently. A silent install can't ask.
    MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "Setup couldn't check whether ${APPNAME} is running. Close \
      ${APPNAME} if it's open, then click OK." /SD IDOK IDOK done
    SetErrorLevel 2
    Abort
  done:
FunctionEnd
!macroend
!insertmacro CloseRunningApp ""
!insertmacro CloseRunningApp "un."

Section "${APPNAME}" SecApp
  SectionIn RO
  Call CloseRunningApp
  !insertmacro RemoveEarlierInstall "UBNT Discovery Reloaded"
  !insertmacro RemoveEarlierInstall "UBNT Discover"
  ; An upgrade replaces the bundled Python and app, so no stale files are left behind: only in a
  ; folder an earlier OpenDisco was installed in (its opendisco.cmd there), never someone else's.
  ${If} ${FileExists} "$INSTDIR\opendisco.cmd"
    RMDir /r "$INSTDIR\python"
    RMDir /r "$INSTDIR\app"
  ${EndIf}
  SetOutPath "$INSTDIR"
  File /r "${STAGE}\*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Shortcuts start in the install folder.
  SetOutPath "$INSTDIR"
  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "${LAUNCHER}" "${LAUNCHARGS}" "${APPICON}" 0
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "${LAUNCHER}" "${LAUNCHARGS}" "${APPICON}" 0

  WriteRegStr HKCU "Software\${APPNAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayName" "${APPNAME} (${FULLNAME})"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTKEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayIcon" "${APPICON}"
  WriteRegStr HKCU "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoRepair" 1
SectionEnd

; Npcap's license doesn't allow bundling it, so this fetches the official installer from npcap.com,
; checks it's signed by Npcap's publisher (Nmap Software LLC) and no one else, and starts its
; installer (which asks for administrator rights itself). Ticked when Npcap isn't installed yet,
; like Wireshark does.
Section /o "Npcap (packet capture for Sniff, Trunk VLANs and Direct)" SecNpcap
  DetailPrint "Getting Npcap from npcap.com..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\app\opendisco\resources\get-npcap.ps1"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Npcap wasn't installed (no internet, or its installer was cancelled). \
      The app offers it again before its first capture; it's also on npcap.com."
  ${EndIf}
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecApp} "The app, with its own copy of Python."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecNpcap} "Downloads Npcap from npcap.com and starts its installer. Needed only \
    for capturing packets: Sniff the wire, Trunk VLANs and Direct to a device. Free for up to 5 computers."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function .onInit
  ; A silent install (/S, how the app updates itself) never offers Npcap: its installer isn't silent.
  ${If} ${Silent}
    Return
  ${EndIf}
  ; A 32-bit installer sees the real System32 as Sysnative.
  ${IfNot} ${FileExists} "$WINDIR\Sysnative\Npcap\wpcap.dll"
  ${AndIfNot} ${FileExists} "$WINDIR\System32\Npcap\wpcap.dll"
    !insertmacro SelectSection ${SecNpcap}
  ${EndIf}
FunctionEnd

; The folder it goes in is one of its own, named OpenDisco (or one an OpenDisco is in already): a
; folder typed without it (the Programs folder, say, where other programs live) would get
; OpenDisco's python and app folders mixed in with theirs.
Function .onVerifyInstDir
  ${GetFileName} "$INSTDIR" $R0
  StrCmp $R0 "${APPNAME}" own
  IfFileExists "$INSTDIR\opendisco.cmd" own
    Abort
  own:
FunctionEnd

Section "Uninstall"
  Call un.CloseRunningApp
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  Delete "$DESKTOP\${APPNAME}.lnk"
  ${If} ${FileExists} "$INSTDIR\opendisco.cmd"  ; (an OpenDisco folder: its own python and app go)
    RMDir /r "$INSTDIR\python"
    RMDir /r "$INSTDIR\app"
  ${EndIf}
  Delete "$INSTDIR\opendisco.cmd"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\NOTICE.txt"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTKEY}"
  DeleteRegKey HKCU "Software\${APPNAME}"
  ; The networks file and settings in %LOCALAPPDATA% are left alone, like most apps do.
SectionEnd
