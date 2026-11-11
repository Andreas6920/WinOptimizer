<div align="center">

<img src="assets/winoptimizer_logo.png" width="360" alt="WinOptimizer — Clean, Setup, Automate" />

# WinOptimizer

### Configure Windows, reduce preinstalled clutter, and install apps

**A PowerShell toolkit for Windows 10 and Windows 11**

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Shell](https://img.shields.io/badge/shell-Windows%20PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)

Choose the interactive menu for a guided start, or run only the commands you need.

</div>

## Quick start

### Start everything in one command

Open **Windows PowerShell as Administrator** and run:

```powershell
$launcher = Join-Path $env:TEMP 'Winoptimizer.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/Winoptimizer.ps1' -OutFile $launcher -UseBasicParsing -ErrorAction Stop; Import-Module -Name $launcher -Force -ErrorAction Stop; Start-WinOptimizer
```

This downloads the launcher from the repository, imports it into the current PowerShell session, and opens the interactive menu. Using the full GitHub URL and explicit error handling makes the download source and failures clearer than the `git.io` shortcut.

### Or pick just what you need

After importing the launcher, call a function directly instead of opening the menu. Each function can be run on its own, and AntiBloat and Windows Settings support switches for selecting specific actions.

## Available sections

### `Start-WinAntiBloat`

Calling `Start-WinAntiBloat` without switches runs all regular sections.

Supported switches:

| Switch | Action |
| --- | --- |
| `-CleanTaskbar` | Clean taskbar features and pinned apps |
| `-CleanLockScreen` | Change lock-screen settings |
| `-CleanStartMenu` | Clean the Start menu |
| `-CleanBloatApps` | Remove selected preinstalled apps |
| `-CleanServices` | Disable selected services |
| `-CleanScheduledTasks` | Disable selected scheduled tasks |
| `-CleanPrinters` | Remove selected printers |
| `-AllPinnedItems` | Run Taskbar, Start menu, and Lock screen sections |
| `-AllBloatware` | Run Apps, Services, Scheduled Tasks, and Printers sections |
| `-CleanDesktop` | Move the current user's desktop contents and clear the Public Desktop |
| `-All` | Run all regular sections; does not include `-CleanDesktop` |

### `Start-WinSecurity`

Run the privacy and security actions:

```powershell
Start-WinSecurity
```

### `Start-WinSettings`

Calling `Start-WinSettings` without switches runs all settings. Use a switch to select a specific setting or group:

| Switch | Action |
| --- | --- |
| `-ShowFileExtension` | Show file extensions |
| `-ShowHiddenFiles` | Show hidden files |
| `-ChangeExplorerToThisPC` | Open File Explorer to This PC |
| `-FixClock` | Show seconds, use a 24-hour clock, and set the short date to `dd/MM/yyyy` |
| `-EnableDarkMode` | Enable Windows dark mode |
| `-SetWallpaperWindowsSpotlight` | Enable the existing Spotlight wallpaper setup |
| `-SetWallpaperDisableWindowsSpotlight` | Disable Spotlight and set the default Windows wallpaper |

### App installation

```powershell
Install-App -Name "Chrome, 7zip, VLC"
Install-App -Name "Office, Chrome, 7zip, VLC" -EnableAutoupdate
```

`Install-App` installs the requested apps and supports optional switches such as `-EnableAutoupdate`.

## What’s included

- **Anti-bloat:** selected built-in apps, Start menu, taskbar, printers, services, and scheduled tasks.
- **Privacy and security:** Windows privacy settings and controls for selected Microsoft tracking domains and IPs.
- **Windows settings:** Explorer preferences, clock and date format, dark mode, and wallpaper options.
- **App installation:** install apps and selected runtimes with the included installer.
- **Interactive menu:** launch the available tools from `Start-WinOptimizer`.

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell
- Administrator privileges for system-wide changes
- Internet access to download the launcher components and selected app installers
