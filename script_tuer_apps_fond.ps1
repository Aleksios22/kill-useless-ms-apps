#Empêcher OneDrive de s'exécuter en arrière-plan

#Fermer OneDrive
Write-Host "Fermeture de OneDrive..."
Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "OneDrive.exe" -Force -ErrorAction SilentlyContinue
Get-Process | Where-Object {$_.ProcessName -like "*OneDrive*"} | Stop-Process -Force -ErrorAction SilentlyContinue

#Désactiver les tâches planifiées OneDrive pour l'empêcher de redémarrer
Write-Host "Désactivation des tâches planifiées OneDrive..."
Get-ScheduledTask | Where-Object {$_.TaskName -like "*OneDrive*"} | Disable-ScheduledTask -ErrorAction SilentlyContinue

#Empêcher OneDrive de s'exécuter en arrière-plan
Write-Host "Configuration de OneDrive..."

# Créer la clé de registre si elle n'existe pas
$OneDriveCheminConfig = "HKCU:\Software\Microsoft\OneDrive"
if (-not (Test-Path $OneDriveCheminConfig)) {
    New-Item -Path $OneDriveCheminConfig -Force | Out-Null
}

Set-ItemProperty -Path $OneDriveCheminConfig -Name "DisableFileSyncNGSC" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $OneDriveCheminConfig -Name "PreventOneDriveFromStarting" -Value 1 -ErrorAction SilentlyContinue

# Désactiver OneDrive au démarrage via la clé de démarrage
$StartupKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Test-Path $StartupKey) {
    Remove-ItemProperty -Path $StartupKey -Name "OneDrive" -ErrorAction SilentlyContinue
}

Write-Host "OneDrive a été configuré pour ne pas démarrer"

# Arrêter les processus Microsoft Edge
Write-Host "Fermeture de Microsoft Edge..."
Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force

# désactiver les tâches planifiées de mise à jour de Microsoft Edge
Write-Host "Configuration de Microsoft Edge..."
schtasks /Change /TN "Microsoft\Windows\MicrosoftEdgeUpdate\MicrosoftEdgeUpdateTaskMachineCore" /Disable 2>$null
schtasks /Change /TN "Microsoft\Windows\MicrosoftEdgeUpdate\MicrosoftEdgeUpdateTaskMachineUA" /Disable 2>$null
reg add "HKCU\Software\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f

Write-Host "Edge stopped and auto-start disabled. Reboot recommended."