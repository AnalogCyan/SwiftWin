# 🔮 SwiftWin

⚠️ This script is a work in progress, some features are unfinished or broken.

Swiftly maintain Windows with ease.

```powershell
SwiftWin.ps1
      [-?]
      [-Verbose]
      [-Reset]
```

## Description

The `SwiftWin.ps1` script runs through a series of Windows maintenance tasks I commonly perform when cleaning up and optimizing a system.

## Options

The script's various functions are split into groups. Each group and its options are listed below.

### Updates

Performs various software update functions.

#### Chocolatey

Check for and install updates in the Chocolatey package manager.

#### Windows Package Manager

Check for and install updates in the Windows Package Manager.

#### Microsoft Store

Check for and install updates in the Microsoft Store.

#### Windows Update

Check for and install Windows updates. Due to how Windows Update handles drivers, the `drivers` updates category is excluded to avoid installing incorrect drivers.

### Virus Scans

Performs virus scans with various antivirus utilities.

#### Microsoft Safety Scanner

#### Malicious Software Removal Tool

#### Kaspersky Virus Removal Tool

#### Malwarebytes ADWCleaner

### Optimize Disks

Perform various disk cleanup and optimization functions.

#### Disk Cleanup

Runs `cleanmgr` with the `/verylowdisk` parameter.

#### Storage Sense

Enables Storage Sense and runs `cleanmgr` with the `/autoclean` parameter.

#### Windows Update

Clears the Windows Update cache.

#### Windows Search

Purge and reinitialize Windows Search.

#### Bleachbit

Runs Bleachbit with the `--clean flash.* internet_explorer.* system.logs system.memory_dump system.recycle_bin system.tmp` parameters.

#### Optimize-Volume

Runs `Optimize-Volume` on all drives with no parameters. This performs the default operation per drive type as follows.

Default operations, quoted from the PowerShell documentation:

> - HDD, Fixed VHD, Storage Space. -Analyze -Defrag.
> - Tiered Storage Space. -TierOptimize.
> - SSD with TRIM support. -Retrim.
> - Storage Space (Thinly provisioned), SAN Virtual Disk (Thinly provisioned), Dynamic VHD, Differencing VHD. -Analyze -SlabConsolidate -Retrim.
> - SSD without TRIM support, Removable FAT, Unknown. No operation.

Further information can be found in the [Optimize-Volume Documentation](https://docs.microsoft.com/en-us/powershell/module/storage/optimize-volume).

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

## Notes

This script assumes you already have knowledge as to how it works, and thus may behave in ways you don't want. This includes but is not limited to: changing system settings, deleting files, and continuing when you'd rather it wait.

I highly advise you have a look at the script for yourself, and modify it to better suit your personal needs, as opposed to blindly running it and hoping for the best.

With all that noted, I do plan on adding more friendly controls in the future.

This script was designed and tested on Windows 11 with PowerShell 7. No guarantees as to how well it'll work on other versions of Windows/PowerShell.

## Links

Below is a list of links to any external resources used in this script.

| Program                      | Link                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Chocolatey                   | [https://chocolatey.org/](https://chocolatey.org/)                                                                                                           |
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
