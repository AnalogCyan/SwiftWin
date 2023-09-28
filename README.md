# 🔮 SwiftWin

![](https://img.shields.io/badge/-Work%20in%20Progress-f00)
![](https://img.shields.io/badge/PowerShell-≥5.1-informational)

Swiftly maintain Windows with ease.

```powershell
SwiftWin.ps1
      [-?]
      [-Verbose]
      [-Reset]
```

> **Note:**
>
> If you haven't allowed the execution of external scripts on your system, you may have to precede the script command with:
>
> `Set-ExecutionPolicy Bypass -Scope Process -Force;`

> You can also quickly get started by running the following in a Windows PowerShell window:
> (this will download a quick-start script for you, install some utilities, and run SwiftWin)
>
> `irm swiftwin.download | iex`

## Description

The `SwiftWin.ps1` script provides a set of Windows maintenance tasks to simplify their execution.

This script was designed and tested on Windows 11 with PowerShell 7. However, it should theoretically work on any modern build of Windows ≥10 with PowerShell ≥5.1. Note that there are no guarantees on its performance on other versions of Windows or PowerShell.

## Options

The script's various functions are split into groups. Each group and its options are listed below.

### Updates

Performs various software update functions.

| Option                  | Description                                                          |
| ----------------------- | -------------------------------------------------------------------- |
| Chocolatey              | Fetch updates from the Chocolatey package manager, if installed.     |
| Scoop                   | Fetch updates from the Scooop package manager, if installed.         |
| Windows Package Manager | Fetch updates from the Windows Package Manager.                      |
| Microsoft Store         | Fetch updates from the Microsoft Store.                              |
| Windows Update          | Fetch Windows updates, excluding the the `drivers` updates category. |

### Virus Scans

Performs virus scans with various antivirus utilities.

| Option                          | Description                                                                           |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| Microsoft Safety Scanner        | Scan & remove medium-to-high threats with Microsoft Safety Scanner                    |
| Malicious Software Removal Tool | Scan & remove medium-to-high threats with Microsoft's Malicious Software Removal Tool |
| Kaspersky Virus Removal Tool    | Scan & remove medium-to-high threats with Kaspersky Virus Removal Tool                |
| Malwarebytes ADWCleaner         | Scan & remove adware and other PUPs with Malwarebytes ADWCleaner                      |

### Optimize Disks

Perform various disk cleanup and optimization functions.

| Option          | Description                                                                                                                            |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Disk Cleanup    | Runs `cleanmgr` with the `/verylowdisk` parameter.                                                                                     |
| Storage Sense   | Enables Storage Sense and runs `cleanmgr` with the `/autoclean` parameter.                                                             |
| Windows Update  | Clears the Windows Update cache.                                                                                                       |
| Windows Search  | Purge and reinitialize Windows Search.                                                                                                 |
| Bleachbit       | Runs Bleachbit with the `--clean flash.* internet_explorer.* system.logs system.memory_dump system.recycle_bin system.tmp` parameters. |
| Optimize-Volume | Runs `Optimize-Volume` on all drives with no parameters. This performs the default operation per drive type.                           |

Default operations for `Optimize-Volume`, quoted from the PowerShell documentation:

> - HDD, Fixed VHD, Storage Space. -Analyze -Defrag.
> - Tiered Storage Space. -TierOptimize.
> - SSD with TRIM support. -Retrim.
> - Storage Space (Thinly provisioned), SAN Virtual Disk (Thinly provisioned), Dynamic VHD, Differencing VHD. -Analyze -SlabConsolidate -Retrim.
> - SSD without TRIM support, Removable FAT, Unknown. No operation.

Further information can be found in the [Optimize-Volume Documentation](https://docs.microsoft.com/en-us/powershell/module/storage/optimize-volume).

### Advanced

| Option            | Description                                                      |
| ----------------- | ---------------------------------------------------------------- |
| Fix Hyper-V Perms | Reslove an issue cause by incorrect Hyper-V file permissions.    |
| Repair System     | Perform Windows system repairs with dism, sfc, & chkdsk.         |
| Disable Services  | Disable the Windows services 'DiagTrack', 'SysMain', & 'WSearch' |
| Clear iOS Cache   | Delete data for iTunes & 3uTools to free up disk space.          |

## Parameters

### -?

Show the script's help text.

```yaml
Accepted values: None
Default value: None
Required: False
```

### -Verbose

Displays extra information about each operation done by the script.

```yaml
Accepted values: None
Default value: None
Required: False
```

### -Reset

Force removal of the script's temporary files. This will delete any files the script has downloaded and reset the scripts current state. This will not delete any generated log files.

```yaml
Accepted values: None
Default value: None
Required: False
```

## Links

Below is a list of links to any external resources used in this script.

| Program                      | Link                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| PowerShell                   | [https://github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell)                                                                         |
| Windows Terminal             | [https://github.com/microsoft/terminal](https://github.com/microsoft/terminal)                                                                               |
| Git for Windows              | [https://github.com/git-for-windows/git](https://github.com/git-for-windows/git)                                                                             |
| gsudo                        | [https://github.com/gerardog/gsudo](https://github.com/gerardog/gsudo)                                                                                       |
| Windows Package Manager      | [https://github.com/microsoft/winget-cli](https://github.com/microsoft/winget-cli)                                                                           |
| Chocolatey                   | [https://chocolatey.org/](https://chocolatey.org/)                                                                                                           |
| Scoop                        | [https://scoop.sh](https://scoop.sh)                                                                                                                         |
| PSWindowsUpdate              | [https://www.powershellgallery.com/packages/PSWindowsUpdate](https://www.powershellgallery.com/packages/PSWindowsUpdate)                                     |
| WinDlg                       | [http://download.wdc.com/windlg/WinDlg_v1_29.zip](http://download.wdc.com/windlg/WinDlg_v1_29.zip)                                                           |
| Bleachbit                    | [https://www.bleachbit.org/](https://www.bleachbit.org/)                                                                                                     |
| Microsoft Safety Scanner     | [https://www.microsoft.com/security/scanner/en-us/default.aspx](https://www.microsoft.com/security/scanner/en-us/default.aspx)                               |
| Kaspersky Virus Removal Tool | [https://www.kaspersky.com/downloads/thank-you/free-virus-removal-tool?form=1](https://www.kaspersky.com/downloads/thank-you/free-virus-removal-tool?form=1) |
| MalwareBytes AdwCleaner      | [https://www.malwarebytes.com/adwcleaner/](https://www.malwarebytes.com/adwcleaner/)                                                                         |
| MalwareBytes Anti-Malware    | [https://www.malwarebytes.com/](https://www.malwarebytes.com/)                                                                                               |
| Uninstall Flash Player       | [https://helpx.adobe.com/flash-player/kb/uninstall-flash-player-windows.html](https://helpx.adobe.com/flash-player/kb/uninstall-flash-player-windows.html)   |

## License

This project is licensed under the [GNU GPLv3](./LICENSE).
