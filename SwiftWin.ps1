#Requires -RunAsAdministrator
#Requires -Version 5.1
# Param()

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
  param (
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.ScriptBlock]$ScriptBlock,

    [Parameter(Mandatory = $true)]
    [string]$DisplayText,

    [Parameter(Mandatory = $false)]
    [string]$LogFilePath = "script_output_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
  )

  # Wrap the contents of the script block in a try/catch block
  $ScriptBlockString = "try { " + $ScriptBlock.ToString() + " } catch { Write-Host `"[ERROR]`" `$_.Exception.Message -ForegroundColor Red }"
  $ScriptBlock = [scriptblock]::Create($ScriptBlockString)

  # Spinner animation characters
  $spinnerChars = '|', '/', '-', '\'

  # Start the script block in the background
  $job = Start-Job -ScriptBlock $ScriptBlock -ErrorVariable jobErrors

  # Display the spinner animation while the script block is running
  $i = 0
  while ($job.State -eq "Running") {
    $spinnerChar = $spinnerChars[$i % $spinnerChars.Length]
    Write-Host -NoNewline -ForegroundColor Blue "[INFO] "
    Write-Host -NoNewline "$DisplayText $spinnerChar`r"
    Start-Sleep -Milliseconds 200
    $i++
  }

  # Clear the spinner animation line
  Write-Host "`r" -NoNewline

  # Display the completion message
  Write-Host -NoNewline -ForegroundColor Blue "[INFO] "
  Write-Host "$DisplayText Completed."

  # Log the script output to a file
  $output = Receive-Job -Job $job
  $output | Out-File -FilePath $LogFilePath

  # Check for and report errors
  if ($jobErrors) {
    Write-Host "Errors:"
    foreach ($error in $jobErrors) {
      Write-Output $error
    }
  }

  # Clean up
  Remove-Job -Job $job
}

function Show-Message {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [Switch]
    $NoNewline,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$MessageType,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$MessageText
  )

  switch ($MessageType) {
    'info' { Write-Host -NoNewline -ForegroundColor Blue "[INFO] " }
    'notice' { Write-Host -NoNewline -ForegroundColor DarkYellow "[NOTICE] " }
    'warn' { Write-Host -NoNewline -ForegroundColor Red "[WARN] " }
    'error' { Write-Host -NoNewline -ForegroundColor Red "[ERROR] " }
    'success' { Write-Host -NoNewline -ForegroundColor Green "[DONE] " }
    default { Write-Host -NoNewline "[UNKNOWN MESSAGE TYPE: $MessageType] " }
  }
  Write-Host -NoNewline:$NoNewline $MessageText
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
  $scriptBlock = {
    Get-ChildItem -Path $using:PSScriptRoot\temp\ -Include * -File -Recurse | ForEach-Object { $_.Delete() }
    Remove-Item -Path $using:PSScriptRoot\temp\* -Recurse -Force -ErrorAction SilentlyContinue
  }
  Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Cleaning up temporary files..."
  exit
}

function Clear-Logs {
  $scriptBlock = {
    Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'logs') -File -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
  }
  Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Cleaning up log files..."
  Show-Menu "logs"
}

<#
.SYNOPSIS
   Executes various security tools based on the specified selection.

.DESCRIPTION
   The Assert-Security function executes different security tools based on the input selection, such as Microsoft Safety Scanner, Malicious Software Removal Tool, Kaspersky Virus Removal Tool, and Malwarebytes ADWCleaner.

.PARAMETER RunSelection
   Specifies which security tool(s) to run. Accepts "msert", "msrt", "kvrt", "adw", or "all".

.EXAMPLE
   Assert-Security -RunSelection "all"
#>
function Assert-Security {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("msert", "msrt", "kvrt", "adw", "all")]
    [String]$RunSelection
  )

  $logOutputPath = Join-Path $PSScriptRoot "logs"
  if ([System.Environment]::Is64BitOperatingSystem) {
    $msert = "https://go.microsoft.com/fwlink/?LinkId=212732"
    $msrt = (Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=9905').Links | ForEach-Object { if ($_ -match "click here to download manually") { $_.href } }
  }
  else {
    $msert = "https://go.microsoft.com/fwlink/?LinkId=212733"
    $msrt = (Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=16').Links | ForEach-Object { if ($_ -match "click here to download manually") { $_.href } }
  }

  function Invoke-Msert {
    $scriptBlock = {
      $progressPreference = 'silentlyContinue'; Invoke-WebRequest -Uri $Using:msert -OutFile $Using:PSScriptRoot\temp\MSERT.exe; Start-Process "$Using:PSScriptRoot\temp\MSERT.exe" -ArgumentList "/Q /F:Y /N" -Verb runAs -Wait
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running MSERT..."
    Start-Sleep -Seconds 2
    Get-Content $env:SystemRoot\debug\msert.log >> $logOutputPath/msert_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }

  function Invoke-Msrt {
    $scriptBlock = {
      $progressPreference = 'silentlyContinue'
      Invoke-WebRequest -Uri $Using:msrt -OutFile $Using:PSScriptRoot\temp\MSRT.exe
      Start-Process "$Using:PSScriptRoot\temp\MSRT.exe" -ArgumentList "/Q /F:Y /N" -Verb runAs -Wait
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running MSRT..."
    Start-Sleep -Seconds 2
    Get-Content C:/Windows/debug/mrt.log >> $logOutputPath/msrt_$(Get-Date -f yyyy-MM-dd)_$(Get-Date -f HH-mm-ss).log
  }

  function Invoke-Kvrt {
    $scriptBlock = {
      $progressPreference = 'silentlyContinue'
      Invoke-WebRequest -Uri 'https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe' -OutFile $Using:PSScriptRoot\temp\KVRT.exe
      Start-Process "$Using:PSScriptRoot\temp\KVRT.exe" -ArgumentList "-accepteula -processlevel 2 -noads -silent -adinsilent -allvolumes" -Verb runAs -Wait
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running KVRT..."
  }

  function Invoke-Adw {
    $scriptBlock = {
      $progressPreference = 'silentlyContinue'
      Invoke-WebRequest -Uri 'https://downloads.malwarebytes.com/file/adwcleaner' -OutFile $Using:PSScriptRoot\temp\ADWCleaner.exe
      Start-Process "$Using:PSScriptRoot\temp\ADWCleaner.exe" -ArgumentList "/eula /clean /noreboot" -Verb runAs -Wait
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running ADWCleaner..."
  }

  Show-Message -MessageType "warn" -MessageText "This option will automatically clean any perceived threats."
  Show-Message -NoNewline -MessageType "warn" -MessageText "This includes medium-to-high threats, and some PUPs. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }
  Show-Message -NoNewline -MessageType "warn" -MessageText "This option will automatically reboot the system when complete. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }

  switch ($RunSelection) {
    "msert" { Invoke-Msert }
    "msrt" { Invoke-Msrt }
    "kvrt" { Invoke-Kvrt }
    "adw" { Invoke-Adw }
    "all" {
      Invoke-Msert
      Invoke-Msrt
      Invoke-Kvrt
      Invoke-Adw
    }
  }
}

function Optimize-Disks {
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("cleanmgr", "sense", "wucache", "wspurge", "bbit", "defrag", "all")]
    [String]$cleanSelection
    
  )

  #region Disk Cleanup
  if ($cleanSelection -eq "cleanmgr" -or $cleanSelection -eq "all") {
    Show-Message -MessageType "notice" -MessageText "Disk cleanup will run in 'verylowdisk' mode and prompt you as if you are low on space."
    Show-Message -MessageType "notice" -MessageText "This is only a result of 'verylowdisk' mode and does not reflect the actual status of your disks."
    $scriptBlock = {
      Start-Process "cleanmgr" -ArgumentList "/verylowdisk" -Verb runAs -Wait
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running Disk Cleanup..."
  }
  #endregion

  #region Storage Sense
  if ($cleanSelection -eq "sense" -or $cleanSelection -eq "all") {
    $scriptBlock = {
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
      & $StorageSense
      Start-Process "cleanmgr" -ArgumentList "/autoclean" -Verb runAs -Wait
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Enabling & Running Storage Sense..."
  }
  #endregion

  #region Clear Windows Update Cache
  if ($cleanSelection -eq "wucache" -or $cleanSelection -eq "all") {
    $scriptBlock = {
      Stop-Service -DisplayName "Background Intelligent Transfer Service" -Force
      Stop-Service -DisplayName "Windows Update" -Force
      Get-ChildItem -ErrorAction Ignore -LiteralPath "C:\Windows\SoftwareDistribution\" -Recurse | Sort-Object { (--$script:i) } | Remove-Item -ErrorAction Ignore
      Remove-Item -ErrorAction Ignore -LiteralPath "C:\Windows\SoftwareDistribution\" -Recurse -Force
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Clearing Windows Update Cache..."
  }
  #endregion

  #region Windows Search Purge & Reinitialize
  if ($cleanSelection -eq "wspurge" -or $cleanSelection -eq "all") {
    $scriptBlock = {
      cmd.exe /c "net stop WSearch"
      cmd.exe /c "if exist 'C:\ProgramData\Microsoft\Search\' RD /S /Q 'C:\ProgramData\Microsoft\Search'"
      Remove-Item -ErrorAction Ignore -Path 'HKCU:\Software\Microsoft\Windows Search' -Recurse -Force
      Remove-ItemProperty -ErrorAction Ignore -Path 'HKLM:\Software\Microsoft\Windows Search' -Name 'SetupCompletedSuccessfully' -Force
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Purging & Reinitializing Windows Search..."
  }
  #endregion

  #region BleachBit
  if ($cleanSelection -eq "bbit" -or $cleanSelection -eq "all") {
    $scriptBlock = {
      $progressPreference = 'silentlyContinue'
      Invoke-WebRequest -Uri https://download.bleachbit.org/BleachBit-4.2.0-portable.zip -OutFile $Using:PSScriptRoot\temp\BleachBit-4.2.0-portable.zip
      Expand-Archive -LiteralPath $Using:PSScriptRoot\temp\BleachBit-4.2.0-portable.zip -DestinationPath $Using:PSScriptRoot\temp
      Start-Process "$Using:PSScriptRoot\temp\BleachBit-Portable\bleachbit_console.exe" -ArgumentList "--update-winapp2" -Verb runAs -Wait
      Start-Process "$Using:PSScriptRoot\temp\BleachBit-Portable\bleachbit_console.exe" -ArgumentList "--clean flash.* internet_explorer.* system.logs system.memory_dump system.recycle_bin system.tmp" -Wait
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running BleachBit..."
  }
  #endregion

  #region Optimize-Volume
  if ($cleanSelection -eq "defrag" -or $cleanSelection -eq "all") {
    $scriptBlock = {
      foreach ($item in $((Get-Volume).DriveLetter.Where({ $null -ne $_ }))) { Optimize-Volume -DriveLetter $item }
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Optimizing Volumes..."
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
      $scriptBlock = {
        choco upgrade all -y
      }
      Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Chocolatey found, updating..."
    }
  }
  #endregion

  #region Scoop
  if ($UpdateSelection -eq "scoop" -or $UpdateSelection -eq "all") {
    Show-Message -MessageType "info" -MessageText "Checking for Scoop..."
    if (Get-Command scoop.ps1 -ErrorAction SilentlyContinue) {
      $scriptBlock = {
        scoop update '*'
      }
      Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Scoop found, updating..."
    }
  }
  #endregion

  #region Windows Package Manager (winget)
  if ($UpdateSelection -eq "winget" -or $UpdateSelection -eq "all") {
    Show-Message -MessageType "info" -MessageText "Checking for Windows Package Manager..."
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
      Show-Message -MessageType "notice" -MessageText "Some applications may individually require and prompt you for admin to update."
      winget upgrade --all
    }
    else {
      Show-Message -MessageType "error" -MessageText "Winget not found, please manually install updates from Windows Update & Microsoft Store."
    }
  }
  #endregion

  #region Microsoft Store
  if ($UpdateSelection -eq "msstore" -or $UpdateSelection -eq "all") {
    $scriptBlock = {
      Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Checking for Microsoft Store updates..."
  }
  #endregion

  #region Windows Update
  if ($UpdateSelection -eq "win-update" -or $UpdateSelection -eq "all") {
    Show-Message -MessageType "notice" -MessageText "Ignoring driver updates to avoid installing incorrect drivers..."
    $scriptBlock = {
      if (-not(Get-Command PSWindowsUpdate -ErrorAction SilentlyContinue)) { Install-Module -ErrorAction SilentlyContinue -Name PSWindowsUpdate -Force }
      Import-Module PSWindowsUpdate; Install-WindowsUpdate -AcceptAll -IgnoreReboot -MicrosoftUpdate -NotCategory "Drivers" -RecurseCycle 2
    }
    Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Checking for Windows Updates..."
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

function Repair-HyperVPerms {
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

function Repair-System {
  Show-Message -NoNewline -MessageType "warn" -MessageText "This option will check the system for corruption, and attempt repairs if any is found. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }

  $scriptBlock = {
    dism /Online /Cleanup-Image /RestoreHealth
  }
  Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running 'dism /Online /Cleanup-Image /RestoreHealth'..."

  $scriptBlock = {
    dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase
  }
  Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running 'dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase'..."

  $scriptBlock = {
    sfc /SCANNOW
  }
  Wait-Animation -ScriptBlock $scriptBlock -DisplayText "Running 'sfc /SCANNOW'..."

  Show-Message -NoNewline -MessageType "notice" -MessageText "Would you like to also run chkdsk? This operation may take a very long time. [y/N] "
  if ($(Read-Host) -Contains "y") { chkdsk /F /R }

  Show-Message -MessageType "notice" -MessageText "A reboot is required to continue; the reboot may take a while depending on the size of your disk and level of corruption found."
  Show-Message -NoNewline -MessageType "notice" -MessageText "The script will open again after rebooting. Press Enter to reboot now."
  Read-Host
  Set-Restart
  Restart-Computer
}

function Disable-Services {
  Show-Message -NoNewline -MessageType "warn" -MessageText "This option will disable the services 'DiagTrack', 'SysMain', & 'WSearch'. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }
  $services = @("Connected User Experiences and Telemetry", "Sysmain", "Windows Search")
  ForEach ($service in $services) {
    $service = Get-Service -Name "$service"
    Write-Output "Stopping service $($service.Name)..."
    Stop-Service -Force -Name $($service.Name)
    Write-Output "Disabling service $($service.Name)..."
    Set-Service -StartupType Disabled -Name $($service.Name)
  }
}

function Clear-iOSCache {
  Show-Message -NoNewline -MessageType "warn" -MessageText "This option will delete ALL DATA for iTunes and 3uTools. Continue? [y/N] "
  if ($(Read-Host) -NotContains "y") { exit }
  Remove-Item -Force -Recurse "C:\3uTools\"
  Remove-Item -Force -Recurse "$env:APPDATA\Apple Computer\"
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
      switch (Get-MenuSelection -MenuPrompt "Updates" -MenuItems "Back", "All", "Chocolatey", "Scoop", "Windows Package Manager", "Microsoft Store", "Windows Update") {
        '0' { Show-Menu "main" }
        '1' { Get-Updates "all" }
        '2' { Get-Updates "choco" }
        '3' { Get-Updates 'scoop' }
        '4' { Get-Updates "winget" }
        '5' { Get-Updates "msstore" }
        '6' { Get-Updates "win-update" }
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
      switch (Get-MenuSelection -MenuPrompt "Advanced" -MenuItems "Back", "Fix Hyper-V Perms", "Repair System", "Disable Services", "iOS Cache Cleanup") {
        '0' { Show-Menu "main" }
        '1' { Repair-HyperVPerms }
        '2' { Repair-System }
        '3' { Disable-Services }
        '4' { Clear-iOSCache }
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
  if ($args.Contains("-?") -Or $args.Contains("/?") -Or $args.Contains("-h") -Or $args.Contains("--help")) { Show-About }
  if ($args.Contains("-Reset")) { Exit-Script }
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
