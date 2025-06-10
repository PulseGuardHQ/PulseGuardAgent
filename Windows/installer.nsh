!macro customHeader
  RequestExecutionLevel admin
!macroend

!macro customInstall
  ; Register the application in Windows uninstall registry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "UninstallString" "${UNINSTALL_DISPLAY_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayIcon" "$INSTDIR\${PRODUCT_NAME}.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "Publisher" "PulseGuard"
  
  ; Request Administrator permissions for the application
  WriteRegStr HKLM "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" \
                   "$INSTDIR\${PRODUCT_NAME}.exe" "RUNASADMIN"
  
  ; Clean up old versions before installing
  DetailPrint "Cleaning up old PulseGuard versions..."
  
  ; Stop any running instances
  nsExec::ExecToLog 'taskkill /F /IM "PulseGuardAgent.exe" /T'
  nsExec::ExecToLog 'taskkill /F /IM "PulseGuard Agent.exe" /T'
  nsExec::ExecToLog 'taskkill /F /IM "pulseguard-agent.exe" /T'
  
  ; Remove old auto-launch entries
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuard Agent"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuard Agent"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuardAgent"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuardAgent"
  
  ; Remove old scheduled tasks
  nsExec::ExecToLog 'schtasks /delete /tn "PulseGuard Agent Startup" /f'
  nsExec::ExecToLog 'schtasks /delete /tn "PulseGuard Startup" /f'
  
  ; Set up auto-startup using multiple methods for reliability
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuardAgent" "$INSTDIR\${PRODUCT_NAME}.exe --startup"
  
  ; Create scheduled task for auto-startup (more reliable)
  nsExec::ExecToLog 'schtasks /create /tn "PulseGuard Agent Startup" /tr "\"$INSTDIR\${PRODUCT_NAME}.exe\" --startup" /sc onlogon /rl highest /f'
!macroend

!macro customUnInstall
  ; Stop the application
  nsExec::ExecToLog 'taskkill /F /IM "${PRODUCT_NAME}.exe" /T'
  
  ; Remove auto-launch entries
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuard Agent"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuard Agent"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuardAgent"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuardAgent"
  
  ; Remove scheduled task
  nsExec::ExecToLog 'schtasks /delete /tn "PulseGuard Agent Startup" /f'
  
  ; Remove application compatibility layer setting
  DeleteRegValue HKLM "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\${PRODUCT_NAME}.exe"
!macroend 