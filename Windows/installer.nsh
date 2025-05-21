!macro customHeader
  RequestExecutionLevel admin
!macroend

!macro customInstall
  ; Add custom installation steps
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuard Agent" "$INSTDIR\${APP_EXECUTABLE_FILENAME} --startup"
!macroend

!macro customUnInstall
  ; Add custom uninstallation steps
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuard Agent"
!macroend 