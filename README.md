<div align="center">

<img src="assets/winoptimizer_logo.png" width="360" alt="WinOptimizer — Clean, Setup, Automate" />

<br/>

# WinOptimizer

### Remove windows bloat, enable privacy, and simplify your Windows Machine

<br/>

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Shell](https://img.shields.io/badge/shell-Windows%20PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)

<br/>

> **Choose the interactive menu for a guided start, or run only the commands you need.**

<br/>

</div>

### Get started in one command

```powershell
$launcher = Join-Path $env:TEMP 'Winoptimizer.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/Winoptimizer.ps1' -OutFile $launcher -UseBasicParsing -ErrorAction Stop; Import-Module -Name $launcher -Force -ErrorAction Stop; Start-WinOptimizer
```

### Or pick just what you need

```powershell
Start-WinAntiBloat -AllBloatware       # Remove Apps, Services, Scheduled Tasks, and Printers bloat
```

```powershell
Start-WinAntiBloat -CleanTaskbar        # Unpin apps and hide taskbar feature buttons
```

```powershell
Start-WinAntiBloat -CleanStartMenu      # Unpin all items from your starmenu
```

```powershell
Start-WinSettings -FixClock    			# Show seconds, use a 24-hour clock in the taskbar
```

```powershell
Start-WinSettings -EnableDarkMode       # Enable Darkmode
```

```powershell
Install-App -Name "Office"              # Install Microsoft Office 2016 Retail (Word, Excel, Powerpoint, Outlook, OneNote)
```

---
