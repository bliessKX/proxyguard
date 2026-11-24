; ProxyGuard installer hooks.
; The installer runs elevated (installMode perMachine), which is the one-time
; authorization for firewall rules. A logon task then starts the guard with
; the highest privilege, so no UAC prompt appears at runtime.

!macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog `taskkill /F /IM proxyguard.exe`
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog `schtasks /Create /TN "ProxyGuard" /TR "\"$INSTDIR\proxyguard.exe\" --background" /SC ONLOGON /RL HIGHEST /F`
  nsExec::ExecToLog `schtasks /Run /TN "ProxyGuard"`
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog `taskkill /F /IM proxyguard.exe`
  ; Remove every firewall block rule the guard created, then the logon task.
  nsExec::ExecToLog `"$INSTDIR\proxyguard.exe" --cleanup`
  nsExec::ExecToLog `schtasks /Delete /TN "ProxyGuard" /F`
!macroend
