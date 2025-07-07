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
  
  DetailPrint "Installing PulseGuard Agent as a Windows Service..."
  
  ; Create a temporary PowerShell script for service installation
  FileOpen $0 "$TEMP\install-service.ps1" w
  FileWrite $0 "$$servicePath = '$INSTDIR\${PRODUCT_NAME}.exe'$\r$\n"
  FileWrite $0 "$$serviceName = 'PulseGuardAgent'$\r$\n"
  FileWrite $0 "$$displayName = 'PulseGuard Agent'$\r$\n"
  FileWrite $0 "$$description = 'The PulseGuard monitoring agent.'$\r$\n"
  FileWrite $0 "$\r$\n"
  FileWrite $0 "if (Get-Service -Name $$serviceName -ErrorAction SilentlyContinue) {$\r$\n"
  FileWrite $0 "    Stop-Service -Name $$serviceName -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "    Start-Sleep -Seconds 2$\r$\n"
  FileWrite $0 "    $$service = Get-WmiObject -Class Win32_Service -Filter $\"Name='$$serviceName'$\"$\r$\n"
  FileWrite $0 "    if ($$service) {$\r$\n"
  FileWrite $0 "        $$service.Delete()$\r$\n"
  FileWrite $0 "        Start-Sleep -Seconds 2$\r$\n"
  FileWrite $0 "    }$\r$\n"
  FileWrite $0 "}$\r$\n"
  FileWrite $0 "$\r$\n"
  FileWrite $0 "New-Service -Name $$serviceName -BinaryPathName $\"$$servicePath$\" --service-mode -DisplayName $$displayName -Description $$description -StartupType Automatic$\r$\n"
  FileWrite $0 "Start-Sleep -Seconds 2$\r$\n"
  FileWrite $0 "Start-Service -Name $$serviceName$\r$\n"
  FileClose $0
  
  ; Run the service installation script with elevated privileges
  DetailPrint "Running service installation script..."
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -File "$TEMP\install-service.ps1"'
  Pop $0
  
  ; Check if service installation was successful
  ${If} $0 != 0
    DetailPrint "Service installation failed. Please check the logs."
  ${EndIf}
  
  ; Clean up the temporary script
  Delete "$TEMP\install-service.ps1"
  
  ; Launch the application UI for the user to configure after installation
  Exec '"$INSTDIR\${PRODUCT_NAME}.exe"'
!macroend

!macro customUnInstall
  DetailPrint "Uninstalling PulseGuard Agent service..."
  
  ; Create a temporary PowerShell script for service uninstallation
  FileOpen $0 "$TEMP\uninstall-service.ps1" w
  FileWrite $0 "$$serviceName = 'PulseGuardAgent'$\r$\n"
  FileWrite $0 "$\r$\n"
  FileWrite $0 "if (Get-Service -Name $$serviceName -ErrorAction SilentlyContinue) {$\r$\n"
  FileWrite $0 "    Stop-Service -Name $$serviceName -Force -ErrorAction SilentlyContinue$\r$\n"
  FileWrite $0 "    Start-Sleep -Seconds 2$\r$\n"
  FileWrite $0 "    $$service = Get-WmiObject -Class Win32_Service -Filter $\"Name='$$serviceName'$\"$\r$\n"
  FileWrite $0 "    if ($$service) {$\r$\n"
  FileWrite $0 "        $$service.Delete()$\r$\n"
  FileWrite $0 "    }$\r$\n"
  FileWrite $0 "}$\r$\n"
  FileClose $0
  
  ; Run the service uninstallation script with elevated privileges
  DetailPrint "Running service uninstallation script..."
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -File "$TEMP\uninstall-service.ps1"'
  Pop $0
  
  ; Clean up the temporary script
  Delete "$TEMP\uninstall-service.ps1"
  
  ; The registry key for uninstall is removed by the main uninstaller
!macroend 