!macro customHeader
  RequestExecutionLevel admin
!macroend

!macro customInstall
  ; Register the application in Windows uninstall registry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayIcon" "$INSTDIR\${PRODUCT_NAME}.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "Publisher" "PulseGuard"
  
  ; Stop any running instances of the old agent
  nsExec::ExecToLog 'taskkill /F /IM "PulseGuardAgent.exe" /T'
  nsExec::ExecToLog 'taskkill /F /IM "PulseGuard Agent.exe" /T'

  DetailPrint "Installing PulseGuard Agent as a Windows Service..."
  
  ; Set the working directory and run the service installation script using Electron's Node runtime
  SetOutPath $INSTDIR
  nsExec::ExecToLog '"$INSTDIR\${PRODUCT_NAME}.exe" "$INSTDIR\resources\app\install-service.js" install'
!macroend

!macro customUnInstall
  DetailPrint "Uninstalling PulseGuard Agent service..."
  
  ; Set the working directory and run the service uninstallation script using Electron's Node runtime
  SetOutPath $INSTDIR
  nsExec::ExecToLog '"$INSTDIR\${PRODUCT_NAME}.exe" "$INSTDIR\resources\app\uninstall-service.js" uninstall'

  ; Stop the application just in case
  nsExec::ExecToLog 'taskkill /F /IM "${PRODUCT_NAME}.exe" /T'
  
  ; The registry key for uninstall is removed by the main uninstaller
!macroend 