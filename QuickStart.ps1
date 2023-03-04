function IsWindowsTerminal ($childProcess) {
  if (!$childProcess) {
    return $false
  }
  elseif ($childProcess.ProcessName -eq 'WindowsTerminal') {
    return $true
  }
  else {
    return IsWindowsTerminal -childProcess $childProcess.Parent
  }
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



function Invoke-SwiftWin {
  $Env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")  
  if (Test-Path "$env:LOCALAPPDATA/SwiftWin/") { Remove-Item -Force -Recurse -ErrorAction SilentlyContinue "$env:LOCALAPPDATA/SwiftWin/" }
  git.exe clone 'https://github.com/AnalogCyan/SwiftWin.git' "$env:LOCALAPPDATA/SwiftWin/"
  Set-ExecutionPolicy Bypass -Scope Process -Force
  pwsh.exe -NoProfile -NoExit -Command "`$Env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User'); gsudo.exe $env:LOCALAPPDATA/SwiftWin/SwiftWin.ps1"
}

if ($(Get-Command pwsh.exe -ErrorAction SilentlyContinue) -and $(Get-Command git.exe -ErrorAction SilentlyContinue) -and $(Get-Command gsudo.exe -ErrorAction SilentlyContinue)) {
  Invoke-SwiftWin
}
else {
  if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
    $Utils = "9MZ1SNWT0N5D", "Git.Git", "gerardog.gsudo"
    foreach ($Util in $Utils) {
      winget install --id "$Util" --silent --force  --accept-package-agreements --accept-source-agreements
    }
    Invoke-SwiftWin
  }
  else {
    Show-Message -MessageType "error" -MessageText "Winget not found, please manually install updates from Windows Update & Microsoft Store and try again."
    exit
  }
}

if (-not $(IsWindowsTerminal)) {
  stop-process -Id $PID
}
