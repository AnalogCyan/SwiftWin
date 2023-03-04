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

function Invoke-SwiftWin {
  $Env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")  
  if (Test-Path "$env:TMP/SwiftWin/") { Remove-Item -Force -Recurse -ErrorAction SilentlyContinue "$env:TMP/SwiftWin/" }
  git.exe clone 'https://github.com/AnalogCyan/SwiftWin.git' "$env:TMP/SwiftWin/"
  Set-ExecutionPolicy Bypass -Scope Process -Force
  pwsh.exe -NoProfile -NoExit -Command "$Env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')); gsudo.exe $env:TMP/SwiftWin/SwiftWin.ps1"
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
