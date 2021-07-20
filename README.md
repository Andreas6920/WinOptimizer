# WinOptimizer
 Optimize your windows machine by removing bloat (like Xbox, Minecraft, bing, ads), optimize your privacy settings, install apps and even enable hidden features!

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
   * Bulk install apps silently<br>
   * Auto app updater, will update all apps automatically when you enjoying lunch.<br>
## Install
open powershell <b>AS ADMIN</b> and run:
```
Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/Winoptimizer.ps1" -OutFile "$env:APPDATA\Winoptimizer.ps1" -UseBasicParsing; cls; powershell -ep bypass "$env:APPDATA\Winoptimizer.ps1"
```

