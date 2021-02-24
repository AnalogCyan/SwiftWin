# 🔮 SwiftWin

Swiftly maintain Windows 10 with ease.

```
SwiftWin.ps1
      [-?]
      [-Verbose]
      [-Reset]
      [-Phase {0 | 1 | 2 | 3 | 4}]
```

## Description

The `SwiftWin.ps1` script runs through a series of Windows 10 maintenance tasks I commonly perform when cleaning up and optimizing a system.

## Phases

The script's execution is split into multiple "phases." Below is a brief description of what each phase entails.

### Phase 0

### Phase 1

### Phase 2

### Phase 3

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

Force removal of the script's temporary files. This will delete any files the script has downloaded and reset the scripts current state, preventing it from resuming a previously unfinished run.

```yaml
Accepted values: None
Default value: None
Required: False
```

### -Phase

Execute only one specific phase of the script. The acceptable values for this parameter are:

- 0
- 1
- 2
- 3

The script will default to running through all phases if none is specified, or attempt to resume at the appropriate phase if previous runs did not conclude in a finished state.

```yaml
Accepted values: 0, 1, 2, 3
Default value: None
Required: False
```

## Notes

This script assumes you already have knowledge as to how it works, and thus may behave in ways you don't want. This includes but is not limited to: changing system settings, deleting files, and continuing when you'd rather it wait.

I highly advise you have a look at the script for yourself, and modify it to better suit your personal needs, as opposed to blindly running it and hoping for the best.

With all that noted, I do plan on adding more friendly controls in the future.

This script was designed and tested on Windows 10 20H2 with PowerShell 7.2.0 and higher. No guarantees as to how well it'll work on other versions of Windows/PowerShell.

## Links

Below is a list of links to any external resources used in this script.

| Program                      | Link                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| WinDlg                       | [http://download.wdc.com/windlg/WinDlg_v1_29.zip](http://download.wdc.com/windlg/WinDlg_v1_29.zip)                                                           |
| Bleachbit                    | [https://www.bleachbit.org/](https://www.bleachbit.org/)                                                                                                     |
| Microsoft Safety Scanner     | [https://www.microsoft.com/security/scanner/en-us/default.aspx](https://www.microsoft.com/security/scanner/en-us/default.aspx)                               |
| Kaspersky Virus Removal Tool | [https://www.kaspersky.com/downloads/thank-you/free-virus-removal-tool?form=1](https://www.kaspersky.com/downloads/thank-you/free-virus-removal-tool?form=1) |
| MalwareBytes AdwCleaner      | [https://www.malwarebytes.com/adwcleaner/](https://www.malwarebytes.com/adwcleaner/)                                                                         |
| MalwareBytes Anti-Malware    | [https://www.malwarebytes.com/](https://www.malwarebytes.com/)                                                                                               |
| Uninstall Flash Player       | [https://helpx.adobe.com/flash-player/kb/uninstall-flash-player-windows.html](https://helpx.adobe.com/flash-player/kb/uninstall-flash-player-windows.html)   |

## License

This project is licensed under the [GNU GPLv3](./LICENSE).
