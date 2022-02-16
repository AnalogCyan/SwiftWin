#Requires -RunAsAdministrator

#region Variables
$ver = "v0.1"
$logo = "
   _____         _ ______ _       ___
  / ___/      __(_) __/ /| |     / (_)___
  \__ \ | /| / / / /_/ __/ | /| / / / __ \
 ___/ / |/ |/ / / __/ /_ | |/ |/ / / / / /
/____/|__/|__/_/_/  \__/ |__/|__/_/_/ /_/

  https://git.thayn.me/SwiftWin | $ver

"
#endregion

#region Functions
function Wait-Animation {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.ScriptBlock]
    $scriptBlock,
    [Parameter(Mandatory = $true)]
    [string]
    $message
  )
  Write-Host -NoNewline -f Blue "[INFO] "
  Write-Host -NoNewline $message
  $cursorTop = [Console]::CursorTop

  try {
    [Console]::CursorVisible = $false

    $counter = 0
    $frames = '|', '/', '-', '\'
    $jobName = Start-Job -ScriptBlock $scriptBlock

    while ($jobName.JobStateInfo.State -eq "Running") {
      $frame = $frames[$counter % $frames.Length]

      Write-Host "$frame" -NoNewline
      [Console]::SetCursorPosition($message.Length + 7, $cursorTop)

      $counter++
      Start-Sleep -Milliseconds 125
    }

    # Only needed if you use a multiline frames
    Write-Host ($frames[0] -replace '[^\s+]', ' ')
  }
  finally {
    [Console]::SetCursorPosition(0, $cursorTop)
    [Console]::CursorVisible = $true
  }
  Write-Host ""
  return $jobName
}

function Show-Message {
  param (
    [Parameter(Mandatory = $false)]
    [Switch]
    $NoNewline,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String[]]$MessageType,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String[]]$MessageText
  )
  switch ($MessageType) {
    'info' {
      Write-Host -NoNewline -f Blue "[INFO] "
      if ($NoNewline) { Write-Host -NoNewline $MessageText }
      else { Write-Host $MessageText }
    }
    'notice' {
      Write-Host -NoNewline -f DarkYellow "[NOTICE] "
      if ($NoNewline) { Write-Host -NoNewline $MessageText }
      else { Write-Host $MessageText }
    }
    'warn' {
      Write-Host -NoNewline -f Red "[WARN] "
      if ($NoNewline) { Write-Host -NoNewline $MessageText }
      else { Write-Host $MessageText }
    }
    'error' {
      Write-Host -NoNewline -f Red "[ERROR] "
      if ($NoNewline) { Write-Host -NoNewline $MessageText }
      else { Write-Host $MessageText }
    }
    'success' {
      Write-Host -NoNewline -f Green "[DONE] "
      if ($NoNewline) { Write-Host -NoNewline $MessageText }
      else { Write-Host $MessageText }
    }
  }
  Start-Sleep -Seconds 1
}

function Set-Restart {
  if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { $runShell = "pwsh.exe" }
  else { $runShell = "powerhell.exe" }
  if (Get-Command wt.exe -ErrorAction SilentlyContinue) { $runTerm = "wt.exe" }
  else { $runTerm = $runShell }
  Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name '!SwiftWin' -Value "powershell.exe -NoProfile -Command Start-Process $runTerm -Verb Runas -ArgumentList '$runShell -NoProfile -NoExit -Command $PSScriptRoot\SwiftWin.ps1'"
}

function Invoke-Setup {
  New-Item -ErrorAction Ignore -Path $PSScriptRoot\logs -ItemType directory
  New-Item -ErrorAction Ignore -Path $PSScriptRoot\temp -ItemType directory | Out-Null
  Get-Item $PSScriptRoot\temp -Force | ForEach-Object { $_.Attributes = $_.Attributes -bor "Hidden" }
  Set-Location $PSScriptRoot
}

function Exit-Script {
  $jobName = Wait-Animation { $(Get-ChildItem -Path $using:PSScriptRoot\temp\ -Include * -File -Recurse | foreach { $_.Delete() }; Remove-Item -Path $using:PSScriptRoot\temp\* -Recurse -Force -ErrorAction SilentlyContinue) } "Cleaning up temporary files..."
  Receive-Job -Job $jobName >> ./logs/cleanup_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  exit
}

function Clear-Logs {
  Wait-Animation { $($logs = Get-ChildItem -Path ./logs -File -Recurse; $logs | ForEach-Object { $_.Delete() }) } "Cleaning up log files..."
  Show-Menu "logs"
}

function Assert-Security {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$runSelection
  )
  #region Variables
  if ([System.Environment]::Is64BitOperatingSystem) {
    $msert = "https://go.microsoft.com/fwlink/?LinkId=212732"
    $msrt = (Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=9905').Links | ForEach-Object { if ($_ -match "click here to download manually") { $_.href } }
  }
  else {
    $msert = "https://go.microsoft.com/fwlink/?LinkId=212733"
    $msrt = (Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=16').Links | ForEach-Object { if ($_ -match "click here to download manually") { $_.href } }
  }
  #endregion

  #region Alerts & Confirmations
  Show-Message -MessageType 'notice' "This option is a work in progress, and does not currently actively clean threats."
  Show-Message -NoNewline -MessageType "warn" -MessageText "This option will automatically clean any perceived threats. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }
  Show-Message -NoNewline -MessageType "warn" -MessageText "This option will automatically reboot the system when complete. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }
  #endregion

  #region Microsoft Safety Scanner
  if ($runSelection -eq "msert" -or $runSelection -eq "all") {
    $jobName = Wait-Animation { $(Invoke-WebRequest -Uri $Using:msert -OutFile $Using:PSScriptRoot\temp\MSERT.exe; Start-Process "$Using:PSScriptRoot\temp\MSERT.exe" -ArgumentList "/Q /N" -Verb runAs -Wait) } "Running MSERT..."
    Get-Content C:/Windows/debug/msert.log >> ./logs/msert_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Malicious Software Removal Tool
  if ($runSelection -eq "msrt" -or $runSelection -eq "all") {
    $jobName = Wait-Animation { $(Invoke-WebRequest -Uri $Using:msrt -OutFile $Using:PSScriptRoot\temp\MSRT.exe; Start-Process "$Using:PSScriptRoot\temp\MSRT.exe" -ArgumentList "/Q /N" -Verb runAs -Wait) } "Running MSRT..."
    Get-Content C:/Windows/debug/mrt.log >> ./logs/msrt_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Kaspersky Virus Removal Tool
  if ($runSelection -eq "kvrt" -or $runSelection -eq "all") {
    $jobName = Wait-Animation { $(Invoke-WebRequest -Uri 'https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe' -OutFile $Using:PSScriptRoot\temp\KVRT.exe; Start-Process "$Using:PSScriptRoot\temp\KVRT.exe" -ArgumentList "-accepteula -processlevel 0 -noads -silent -allvolumes" -Verb runAs -Wait) } "Running KVRT..."
    Receive-Job -Job $jobName >> ./logs/kvrt_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Malwarebytes ADWCleaner
  if ($runSelection -eq "adw" -or $runSelection -eq "all") {
    $jobName = Wait-Animation { $(Invoke-WebRequest -Uri 'https://downloads.malwarebytes.com/file/adwcleaner' -OutFile $Using:PSScriptRoot\temp\ADWCleaner.exe; Start-Process "$Using:PSScriptRoot\temp\ADWCleaner.exe" -ArgumentList "/eula /scan /noreboot" -Verb runAs -Wait) } "Running ADWCleaner..."
    Receive-Job -Job $jobName >> ./logs/adw_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion
}

function Optimize-Disks {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$cleanSelection
  )
  #region Variables
  $StorageSense = {
    ## Enable Storage Sense
    ## Ensure the StorageSense key exists
    $key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense"
    If (!(Test-Path "$key")) {
      New-Item -Path "$key" | Out-Null
    }
    If (!(Test-Path "$key\Parameters")) {
      New-Item -Path "$key\Parameters" | Out-Null
    }
    If (!(Test-Path "$key\Parameters\StoragePolicy")) {
      New-Item -Path "$key\Parameters\StoragePolicy" | Out-Null
    }

    ## Set Storage Sense settings
    ## Enable Storage Sense
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1

    ## Set 'Run Storage Sense' to Every Week
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "2048" -Type DWord -Value 7

    ## Enable 'Delete temporary files that my apps aren't using'
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 1

    ## Set 'Delete files in my recycle bin if they have been there for over' to 30 days
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "08" -Type DWord -Value 1
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "256" -Type DWord -Value 30

    ## Set 'Delete files in my Downloads folder if they have been there for over' to never
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "32" -Type DWord -Value 0
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "512" -Type DWord -Value 0

    ## Set value that Storage Sense has already notified the user
    Set-ItemProperty -Path "$key\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1
  }
  #endregion

  #region Alerts & Confirmation
  Show-Message -MessageType "notice" -MessageText "Disk cleanup will run in 'verylowdisk' mode and prompt you as if you are low on space."
  Show-Message -MessageType "notice" -MessageText "This is only a result of 'verylowdisk' mode and does not reflect the actual status of your disks."
  #endregion

  #region Disk Cleanup
  if ($cleanSelection -eq "cleanmgr" -or $cleanSelection -eq "all") {
    $jobName = Wait-Animation { $(Start-Process "cleanmgr" -ArgumentList "/verylowdisk" -Verb runAs -Wait) } "Running Disk Cleanup..."
    Receive-Job -Job $jobName >> ./logs/cleanmgr_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Storage Sense
  if ($cleanSelection -eq "sense" -or $cleanSelection -eq "all") {
    $jobName = Wait-Animation { $(Invoke-Expression $using:StorageSense) } "Enabling Storage Sense..."
    Receive-Job -Job $jobName >> ./logs/cleanmgr_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
    $jobName = Wait-Animation { $( Start-Process "cleanmgr" -ArgumentList "/autoclean" -Verb runAs -Wait ) } "Running Storage Sense..."
    Receive-Job -Job $jobName >> ./logs/cleanmgr_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Clear Windows Update Cache
  if ($cleanSelection -eq "wucache" -or $cleanSelection -eq "all") {
    $jobName = Wait-Animation { $(Stop-Service -DisplayName "Background Intelligent Transfer Service" -Force; Stop-Service -DisplayName "Windows Update" -Force; Get-ChildItem -ErrorAction Ignore -LiteralPath "C:\Windows\SoftwareDistribution\" -Recurse | Sort-Object { (--$script:i) } | Remove-Item -ErrorAction Ignore; Remove-Item -ErrorAction Ignore -LiteralPath "C:\Windows\SoftwareDistribution\" -Recurse -Force) } "Clearing Windows Update cache..."
    Receive-Job -Job $jobName >> ./logs/wucache_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Windows Search Purge & Reinitialize
  if ($cleanSelection -eq "wspurge" -or $cleanSelection -eq "all") {
    $jobName = Wait-Animation { $(cmd.exe /c "net stop WSearch"; cmd.exe /c "RD /S /Q 'C:\ProgramData\Microsoft\Search'"; Remove-Item -Path 'HKCU:\Software\Microsoft\Windows Search' -Recurse -Force; Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows Search' -Name 'SetupCompletedSuccessfully' -Force) } "Cleaning & Reinitializing Windows Search..."
    Receive-Job -Job $jobName >> ./logs/wspurge_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region BleachBit
  if ($cleanSelection -eq "bbit" -or $cleanSelection -eq "all") {
    $jobName = Wait-Animation { $(Invoke-WebRequest -Uri https://download.bleachbit.org/BleachBit-4.2.0-portable.zip -OutFile $Using:PSScriptRoot\temp\BleachBit-4.2.0-portable.zip; Expand-Archive -LiteralPath $Using:PSScriptRoot\temp\BleachBit-4.2.0-portable.zip -DestinationPath $Using:PSScriptRoot\temp; Start-Process "$Using:PSScriptRoot\temp\BleachBit-Portable\bleachbit_console.exe" -ArgumentList "--update-winapp2" -Verb runAs -Wait; Start-Process "$Using:PSScriptRoot\temp\BleachBit-Portable\bleachbit_console.exe" -ArgumentList "--clean flash.* internet_explorer.* system.logs system.memory_dump system.recycle_bin system.tmp" -Wait) } "Running BleachBit..."
    Receive-Job -Job $jobName >> ./logs/bbit_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Optimize-Volume
  if ($cleanSelection -eq "defrag" -or $cleanSelection -eq "all") {
    $jobName = Wait-Animation { $($drives = (Get-PSDrive).Name -match '^[a-z]$'; foreach ($item in $drives) { Optimize-Volume -DriveLetter $item }) } "Optimizing Disks..."
    Receive-Job -Job $jobName >> ./logs/optimize_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion
}

function Get-Updates {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$UpdateSelection
  )
  #region Alerts & Confirmation
  Show-Message -NoNewline -MessageType "warn" -MessageText "This option will automatically reboot the system if there are updates that request it. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }
  Show-Message -MessageType "notice" -MessageText "Some updates may spawn new windows (sometimes in the background) which require user interaction to complete."
  #endregion

  #region Chocolatey
  if ($UpdateSelection -eq "choco" -or $UpdateSelection -eq "all") {
    Show-Message -MessageType "info" -MessageText "Checking for Chocolatey..."
    if (Get-Command chocolatey.exe -ErrorAction SilentlyContinue) {
      $jobName = Wait-Animation { $(choco upgrade all -y) } "Chocolatey found, updating..."
      Receive-Job -Job $jobName >> ./logs/choco_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
    }
    else {
      $jobName = Wait-Animation { $(Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))) } "Chocolatey not found, installing..."
      Receive-Job -Job $jobName >> ./logs/choco_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
    }
  }
  #endregion

  #region Windows Package Manager (winget)
  if ($UpdateSelection -eq "winget" -or $UpdateSelection -eq "all") {
    Show-Message -MessageType "info" -MessageText "Checking for Windows Package Manager..."
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
      $jobName = Wait-Animation { $(winget upgrade --all) } "Windows Package Manager found, updating..."
      Receive-Job -Job $jobName >> ./logs/winget_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
    }
  }
  #endregion

  #region Microsoft Store
  if ($UpdateSelection -eq "msstore" -or $UpdateSelection -eq "all") {
    $jobName = Wait-Animation { $(Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod) } "Checking for Microsoft Store updates..."
    Receive-Job -Job $jobName >> ./logs/msstore_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  #region Windows Update
  if ($UpdateSelection -eq "win-update" -or $UpdateSelection -eq "all") {
    Show-Message -MessageType "notice" -MessageText "Ignoring driver updates to avoid installing incorrect drivers..."
    $jobName = Wait-Animation { $(if (-not(Get-Command PSWindowsUpdate -ErrorAction SilentlyContinue)) { Install-Module -ErrorAction SilentlyContinue -Name PSWindowsUpdate -Force }; Import-Module PSWindowsUpdate; Install-WindowsUpdate -AcceptAll -IgnoreReboot -MicrosoftUpdate -NotCategory "Drivers" -RecurseCycle 2) } "Checking for Windows Updates..."
    Receive-Job -Job $jobName >> ./logs/winupdate_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }
  #endregion

  Show-Message -MessageType "success" -MessageText "Updates completed. Logs can be found in $PSScriptRoot\logs."
  if ($(Get-WURebootStatus -Silent) -contains "True") {
    Show-Message -NoNewline -MessageType "notice" -MessageText "Updates require a reboot; the script will open again after rebooting. Press Enter to reboot now."
    Read-Host
    Set-Restart
    Get-WURebootStatus -AutoReboot
  }
}

function Get-Advanced {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$AdvancedSelection
  )
  #region Fix Hyper-V Perms
  if ($AdvancedSelection -eq "hyperv") {
    #Import the NTFSSecurity Module, if not available, prompt to download it
    If ((Get-Module).Name -notcontains 'NTFSSecurity') {
      Write-Warning "This script depends on the NTFSSecurity Module, by MSFT"
      if ($PSVersionTable.PSVersion.Major -ge 4) {
        Write-Output "This script can attempt to download this module for you..."
        $DownloadMod = Read-Host "Continue (y/n)?"

        if ($DownloadMod.ToUpper() -like "Y*") {
          Find-Module NTFSSecurity | Install-Module
        }
        else {
          #User responded No, end
          Write-Warning "Please download the NTFSSecurity module and continue"
          break
        }

      }
      else {
        #Not running PowerShell v4 or higher
        Write-Warning "Please download the NTFSSecurity module and continue"
        break
      }
    }
    else {
      #Import the module, as it exists
      Import-Module NTFSSecurity

    }

    $VMs = Get-VM
    ForEach ($VM in $VMs) {
      $disks = Get-VMHardDiskDrive -VMName $VM.Name
      Write-Output "This VM $($VM.Name), contains $($disks.Count) disks, checking permissions..."

      ForEach ($disk in $disks) {
        $permissions = Get-NTFSAccess -Path $disk.Path
        If ($permissions.Account -notcontains "NT Virtual Mach*") {
          $disk.Path
          Write-Host "This VHD has improper permissions, fixing..." -NoNewline
          try {
            Add-NTFSAccess -Path $disk.Path -Account "NT VIRTUAL MACHINE\$($VM.VMId)" -AccessRights FullControl -ErrorAction STOP
          }
          catch {
            Write-Host -ForegroundColor red "[ERROR]"
            Write-Warning "Try rerunning as Administrator, or validate your user ID has FullControl on the above path"
            break
          }

          Write-Host -ForegroundColor Green "[OK]"

        }

      }
    }
  }
  #endregion

  #region Repair System
  if ($AdvancedSelection -eq "repair") {
    Show-Message -NoNewline -MessageType "warn" -MessageText "This option will check the system for corruption, and attempt repairs if any is found. Continue? [y/N] "
    if ($(Read-Host) -NotContains "y") { exit }
    dism /Online /Cleanup-Image /RestoreHealth
    dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase
    sfc /SCANNOW
    chkdsk /F /R
    Show-Message -MessageType "notice" -MessageText "A reboot is required to continue; the reboot may take a while depending on the size of your disk and level of corruption found."
    Show-Message -NoNewline -MessageType "notice" -MessageText "The script will open again after rebooting. Press Enter to reboot now."
    Read-Host
    Set-Restart
    Restart-Computer
  }
  #endregion

  #region Install Utils
  if ($AdvancedSelection -eq "utils") {
    Show-Message -NoNewline -MessageType "warn" -MessageText "This option will attempt to install/update some useful system utilities. Continue? [y/N] "
    if ($(Read-Host) -NotContains "y") { exit }
    winget install --id=Microsoft.PowerShell -e -h --force ; winget install --id=Microsoft.WindowsTerminal -e -h --force ; winget install --id=Git.Git -e -h --force
  }
  #endregion

  #region WSL2
  if ($AdvancedSelection -eq "wsl2") {
    Show-Message -NoNewline -MessageType "warn" -MessageText "This option will attempt to install/update WSL2. Continue? [y/N] "
    if ($(Read-Host) -NotContains "y") { exit }
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
    Invoke-WebRequest -Uri 'https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi' -OutFile $PSScriptRoot\temp\wsl_update_x64.msi
    Start-Process ".\temp\wsl_update_x64.msi" -Wait
    wsl --set-default-version 2
    Show-Message -MessageType "notice" -MessageText "A reboot is required to continue; the script will open again after rebooting. Press Enter to reboot now."
    Read-Host
    Set-Restart
    Restart-Computer -Confirm
  }
  #endregion
}

<#
.SYNOPSIS
Display a menu and get user selection.

.DESCRIPTION
Display a menu and get user selection.
Takes any strings for the menu prompt and items.

.PARAMETER MenuPrompt
Specifies the menu prompt's title.

.PARAMETER MenuItems
Specifies the available menu options.

.EXAMPLE
Get-MenuSelection -MenuPrompt "Main Menu" -MenuItems "Option 0", "Option 1", "Option 2", "Option 3", "Option 4"
#>
function Get-MenuSelection {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$MenuPrompt,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String[]]$MenuItems
  )
  Clear-Host
  Write-Host $logo
  Write-Host $MenuPrompt
  Write-Host "=========================================="
  Write-Host " CHOICE                     FUNCTION"
  $i = 0
  foreach ($item in $MenuItems) {
    Write-Host -NoNewline -f Green " Enter '${i}':                 "
    Write-Host $item
    $i++
  }
  Write-Host "=========================================="
  Write-Host -NoNewline -f Yellow "Enter Choice: "
  $userInput = Read-Host
  Write-Host ""
  return $userInput
}

<#
.SYNOPSIS
Displays the script's about.txt.

.DESCRIPTION
Displays the script's about.txt.
Does not take any parameters.
#>
function Show-About {
  Clear-Host
  Get-Content .\about.txt
  exit
}

function Show-Menu {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$Menu
  )
  switch ($Menu) {
    'main' {
      switch (Get-MenuSelection -MenuPrompt "Main Menu" -MenuItems "Exit", "About", "Logs", "Updates", "Virus Scans", "Optimize Disks", "Advanced") {
        '0' { Exit-Script }
        '1' { Show-About }
        '2' { Show-Menu "logs" }
        '3' { Show-Menu "updates" }
        '4' { Show-Menu "scans" }
        '5' { Show-Menu "disks" }
        '6' { Show-Menu "advanced" }
      }
    }
    'logs' {
      switch (Get-MenuSelection -MenuPrompt "Logs" -MenuItems "Back", "View Logs", "Clear Logs") {
        '0' { Show-Menu "main" }
        '1' { explorer.exe .\logs }
        '2' { Clear-Logs }
      }
    }
    'updates' {
      switch (Get-MenuSelection -MenuPrompt "Updates" -MenuItems "Back", "All", "Chocolatey", "Windows Package Manager", "Microsoft Store", "Windows Update") {
        '0' { Show-Menu "main" }
        '1' { Get-Updates "all" }
        '2' { Get-Updates "choco" }
        '3' { Get-Updates "winget" }
        '4' { Get-Updates "msstore" }
        '5' { Get-Updates "win-update" }
      }
    }
    'scans' {
      switch (Get-MenuSelection -MenuPrompt "Virus Scans" -MenuItems "Back", "All", "Microsoft Safety Scanner", "Malicious Software Removal Tool", "Kaspersky Virus Removal Tool", "Malwarebytes ADWCleaner") {
        '0' { Show-Menu "main" }
        '1' { Assert-Security "all" }
        '2' { Assert-Security "msert" }
        '3' { Assert-Security "msrt" }
        '4' { Assert-Security "kvrt" }
        '5' { Assert-Security "adw" }
      }
    }
    'disks' {
      switch (Get-MenuSelection -MenuPrompt "Optimize Disks" -MenuItems "Back", "All", "Disk Cleanup", "Storage Sense", "Windows Update", "Windows Search", "Bleachbit", "Optimize-Volume") {
        '0' { Show-Menu "main" }
        '1' { Optimize-Disks "all" }
        '2' { Optimize-Disks "cleanmgr" }
        '3' { Optimize-Disks "sense" }
        '4' { Optimize-Disks "wucache" }
        '5' { Optimize-Disks "wspurge" }
        '6' { Optimize-Disks "bbit" }
        '7' { Optimize-Disks "defrag" }
      }
    }
    'advanced' {
      switch (Get-MenuSelection -MenuPrompt "Advanced" -MenuItems "Back", "Fix Hyper-V Perms", "Repair System", "Install Utils", "Enable WSL2") {
        '0' { Show-Menu "main" }
        '1' { Get-Advanced "hyperv" }
        '2' { Get-Advanced "repair" }
        '3' { Get-Advanced "utils" }
        '4' { Get-Advanced "wsl2" }
      }
    }
    Default {
      Show-Message -MessageType "error" -MessageText "Invalid menu selection."
    }
  }
}

function Get-Args {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $args
  )
  if ($args.Contains("-?")) { Show-About }
  if ($args.Contains("-Reset")) { Reset-Script }
  if ($args.Contains("-Verbose")) { Switch-Verbosity }
  exit
}
#endregion

#region Main
if ($args) { Get-Args $args }
Invoke-Setup
Show-Menu "main"
Exit-Script
#endregion
