$version = "REPLACE-ME-FULLNAME"

# Windows notification 1
    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = ‘Installing ' + $version + '...'
    $balmsg.BalloonTipTitle = "Microsoft Office"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)

# Installation
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Get-AppxPackage | Where-Object Name -Match "Microsoft.MicrosoftOfficeHub|Microsoft.Office.OneNote" | Remove-AppxPackage;
    New-BurntToastNotification -Applogo $logo -Text "Microsoft Office", "Program installed! Enjoy."

# Windows notification 2
    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = ‘Installation complete!'
    $balmsg.BalloonTipTitle = "Microsoft Office"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)