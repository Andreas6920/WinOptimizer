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

### Install in one command

```powershell
& ([ScriptBlock]::Create((Invoke-RestMethod 'https://git.io/JzrB5')))
```

### .. Or pick just what you need

Remove Apps, Services, Scheduled Tasks, and Printers bloat
```powershell
& ([ScriptBlock]::Create((Invoke-RestMethod 'https://git.io/JzrB5'))) -InstallOnly; Start-WinAntiBloat -AllBloatware
```

Unpin apps and hide taskbar feature buttons
```powershell
& ([ScriptBlock]::Create((Invoke-RestMethod 'https://git.io/JzrB5'))) -InstallOnly; Start-WinAntiBloat -CleanTaskbar
```

Unpin all items from your starmenu
```powershell
& ([ScriptBlock]::Create((Invoke-RestMethod 'https://git.io/JzrB5'))) -InstallOnly; Start-WinAntiBloat -CleanStartMenu
```

Show seconds, use a 24-hour clock in the taskbar
```powershell
& ([ScriptBlock]::Create((Invoke-RestMethod 'https://git.io/JzrB5'))) -InstallOnly; Start-WinSettings -FixClock
```

Enable Darkmode
```powershell
& ([ScriptBlock]::Create((Invoke-RestMethod 'https://git.io/JzrB5'))) -InstallOnly; Start-WinSettings -EnableDarkMode
```

Install Microsoft Office 2016 Retail (Word, Excel, Powerpoint, Outlook, OneNote)
```powershell
& ([ScriptBlock]::Create((Invoke-RestMethod 'https://git.io/JzrB5'))) -InstallOnly; Install-App -Name "Office"
```

---
