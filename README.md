# WinOptimizer
 Optimize your windows system by removing bloat (like Xbox, Minecraft, bing, ads), optimize your privacy settings, install apps and even enable hidden features!

## Modules
 * <b>Cleaning Windows 10 from bloat</b><br>
   * Removing Bing search, weather, travel, news etc..<br>
   * Removing Xbox, Minecraft and other stuff..<br>
   * Remove windows scheduled tasks for bloat reinstallation/updates..<br>
   * Removing tiles from start menu, it makes the design way more cleaner.<br>
   * Removing pinned programs in the taskbar, so you can pin your own..<br>
   * Remove Microsoft pre–installed printers. (fax, onenote etc..)<br>
 * <b>Optimizing your privacy on Windows 10</b><br>
   * Disabling ads, tracking, diagnostics.<br>
   * Removing tracking services from windows startup..<br>
   * Blocking Microsoft tracking domains from collecting data from your browsing activity.<br>
   * Sends a request to Microsoft to delete all data they already have collected about your computer.<br>
 * <b>Customize the PC</b><br>
   * Cortana removal<br>
   * Dark Mode<br>
   * Disable logon screensaver, searhbox, taskview, 3D Objects..<br>
   * Show filetype, hidden files<br>
   * Install Hyper–V, Linux<br>
 * <b>Appinstaller</b><br>
   * All-in-one .NET Framework installer<br>
   * All-in-one Microsoft Visual C++ installer<br>
   * Bulk install apps silently in the background<br>
   * Auto app updater, will update all apps automatically when you enjoying lunch.<br>
   * Microsoft Office installation in the background<br>
## Install
open powershell <b>AS ADMIN</b> and run:
```

$a = "$env:TMP\win.ps1"; iwr -useb https://git.io/JzrB5 -O $a; ipmo $a; Start-WinOptimizerUI

```
