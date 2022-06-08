$version = "REPLACE-ME-FULLNAME"

# Windows notification 1
    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = 'Installing ' + $version + '...'
    $balmsg.BalloonTipTitle = "Microsoft Office"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)

# Installation
    Get-AppxPackage | Where-Object Name -Match "Microsoft.MicrosoftOfficeHub|Microsoft.Office.OneNote" | Remove-AppxPackage;
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    choco install microsoft-office-deployment /64bit /Product REPLACE-ME-VERSION /language REPLACE-ME-LANGUAGE -y
    

# Windows notification 2
    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = 'Installation complete!'
    $balmsg.BalloonTipTitle = "Microsoft Office"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)