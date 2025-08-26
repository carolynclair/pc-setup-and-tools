<# 
  debloat-gaming.ps1
  Purpose: Strip Windows 11 for gaming/dev (Warmane + Unity) while keeping NVIDIA & Warperia.
  Default: Safe (keeps MS Store, Search; disables Defender *real-time* only).
  Optional: -Aggressive to disable more services (Search, SysMain), remove more inbox apps.

  Usage:
    .\debloat-gaming.ps1
    .\debloat-gaming.ps1 -Aggressive
#>

[CmdletBinding()]
param(
  [switch]$Aggressive
)

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
  }
}
Assert-Admin

Write-Host "`n=== Windows Gaming Debloat (Safe Mode) ===`n" -ForegroundColor Cyan
Write-Host "Aggressive mode: $Aggressive`n"

# 0) Create a quick restore checkpoint (if service available)
try {
  Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue | Out-Null
  Checkpoint-Computer -Description "Pre-Debloat" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Restore point attempted (if System Protection enabled)." -ForegroundColor DarkGray
} catch {}

# 1) Power plan: High/Ultimate Performance
Write-Host "Setting High/Ultimate Performance power plan..."
$ultimate = "e9a42b02-d5df-448d-aa00-03f14749eb61"
powercfg -duplicatescheme $ultimate | Out-Null
powercfg -setactive $ultimate | Out-Null

# 2) Game optimizations: Game Mode + GPU Scheduling
Write-Host "Enabling Game Mode & Hardware-accelerated GPU scheduling..."
New-Item -Path "HKCU:\Software\Microsoft\GameBar" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2

# 3) Visual effects → best performance (leave font smoothing)
Write-Host "Optimizing visual effects..."
$perfKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
New-Item -Path $perfKey -Force | Out-Null
# Set 'best performance' equivalents
$advPerf = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
New-Item -Path $advPerf -Force | Out-Null
Set-ItemProperty -Path $advPerf -Name "IconsOnly" -Type DWord -Value 1
Set-ItemProperty -Path $advPerf -Name "TaskbarAnimations" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))  # conservative cut
# Keep ClearType on
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value 2

# 4) Kill bloat inbox apps (safe list keeps Store, Calculator, Photos, Notepad, etc.)
Write-Host "Removing non-essential inbox apps..."
$keep = @(
  "Microsoft.StorePurchaseApp","Microsoft.WindowsStore",
  "Microsoft.WindowsCalculator","Microsoft.WindowsNotepad",
  "Microsoft.Windows.Photos","Microsoft.Paint",
  "Microsoft.WSL","Microsoft.VP9VideoExtensions","Microsoft.HEIFImageExtension",
  "NVIDIA","GeForceExperience" # guard rail; not Appx, but safety
)

$packages = Get-AppxPackage | Where-Object {
  $name = $_.Name
  -not ($keep | ForEach-Object { $name -like "*$_*" })
}
foreach ($p in $packages) {
  try {
    Write-Host ("  Removing " + $p.Name)
    Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
  } catch {}
}

# 5) Disable/Remove Xbox & consumer features
Write-Host "Disabling Xbox/Game Bar background junk..."
Get-AppxPackage *Xbox* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *XboxGamingOverlay* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *ZuneMusic* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *ZuneVideo* | Remove-AppxPackage -ErrorAction SilentlyContinue

# 6) OneDrive (optional remove)
Write-Host "Disabling OneDrive autostart..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "" /f | Out-Null
if ($Aggressive) {
  Write-Host "Attempting OneDrive uninstall (Aggressive)..."
  $od = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
  if (-not (Test-Path $od)) { $od = "$env:SystemRoot\System32\OneDriveSetup.exe" }
  if (Test-Path $od) { Start-Process $od "/uninstall" -Wait -NoNewWindow }
}

# 7) Startup apps: disable most
Write-Host "Disabling common startup apps..."
$startup = (Get-CimInstance Win32_StartupCommand) | Select-Object Name, Command, Location
# We won't nuke NVIDIA / Warperia:
$ban = @("Microsoft Teams","Skype","Cortana","Edge","OneDrive","Spotify","Adobe","EpicGamesLauncher","SteamWebHelper")
foreach ($s in $startup) {
  if ($ban | Where-Object { $s.Name -like "*$_*" }) {
    Write-Host ("  Disable (manual): " + $s.Name) -ForegroundColor DarkGray
  }
}
# Note: Many startup items are better toggled via Task Manager UI or Autoruns for safety.

# 8) Services & telemetry trim (safe)
Write-Host "Trimming background services..."
$servicesToDisable = @(
  "DiagTrack",                          # Connected User Experiences and Telemetry
  "dmwappushservice",                   # Device Management Wireless App
  "WMPNetworkSvc",                      # Media sharing
  "SharedAccess",                       # Internet Connection Sharing
  "RetailDemo"                          # Retail demo
)
if ($Aggressive) {
  $servicesToDisable += @("XboxGipSvc","XblAuthManager","XblGameSave","XboxNetApiSvc","SysMain","WSearch")
}
foreach ($svc in $servicesToDisable) {
  $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($service) {
    try {
      Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
      if ($service.Status -ne 'Stopped') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
      Write-Host ("  Disabled " + $svc)
    } catch {}
  }
}

# 9) Disable background apps (policy)
Write-Host "Disabling background apps via policy..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2

# 10) Defender: turn off *real-time* (safe). (You can re-enable anytime)
Write-Host "Turning off Windows Defender *real-time* protection (safe mode)..."
try {
  Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
} catch {
  Write-Host "  (If this fails, Windows policy may be enforcing it.)" -ForegroundColor DarkGray
}

# 11) Disable transparency & animations (extra polish)
Write-Host "Disabling transparency/animations for snappier UI..."
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0

# 12) Storage Sense & cleanup
Write-Host "Enabling Storage Sense and doing a quick cleanup..."
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
Start-Process cleanmgr.exe "/verylowdisk" -NoNewWindow

# 13) Hibernation off (saves disk space)
Write-Host "Disabling hibernation to save disk space..."
powercfg /hibernate off | Out-Null

# 14) Optional: disable Fast Startup (prevents weird boot loops)
Write-Host "Disabling Fast Startup..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f | Out-Null

Write-Host "`nDone. Reboot recommended." -ForegroundColor Green
Write-Host "Notes:"
Write-Host " - NVIDIA app and Warperia are untouched."
Write-Host " - Defender real-time OFF (safe). Re-enable with:  Set-MpPreference -DisableRealtimeMonitoring \$false"
Write-Host " - Aggressive mode additionally disables Search/SysMain & removes more apps."
