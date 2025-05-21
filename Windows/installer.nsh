!macro customHeader
  RequestExecutionLevel admin
!macroend

!macro customInstall
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "UninstallString" "${UNINSTALL_DISPLAY_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}" \
                   "DisplayIcon" "$INSTDIR\${PRODUCT_NAME}.exe"
  
  ; Request Administrator permissions for the application
  WriteRegStr HKLM "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" \
                   "$INSTDIR\${PRODUCT_NAME}.exe" "RUNASADMIN"
!macroend

!macro customUnInstall
  ; Add custom uninstallation steps
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "PulseGuard Agent"
!macroend 