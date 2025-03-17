# Microsoft .NET Framework

    # Prepare system
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
        Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1

    # Install NET Framework Version 3.5 (Version 2.0 and 3.0 included)
        $job1 = "Install .NET Framework 3.5"
        Start-Job -Name $job1 -ScriptBlock {
        If (!(Test-Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing)) {
        New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing | Out-Null}    
        Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing -Name RepairContentServerSource -Type DWord -Value 2
        Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" | Out-Null}

    # Install Latest NET Framework version
        $version = ((Invoke-WebRequest -Uri 'https://dotnet.microsoft.com/en-us/download/dotnet-framework' | Select-Object -ExpandProperty Links | Where-Object innerHTML -match '.Net Framework' | Select-Object -First 1 ).InnerHTML).trim()
        $job2 = "Install $Version"
        Start-Job -Name $job2 -ScriptBlock {
        $version = ((Invoke-WebRequest -Uri 'https://dotnet.microsoft.com/en-us/download/dotnet-framework' | Select-Object -ExpandProperty Links | Where-Object innerHTML -match '.Net Framework' | Select-Object -First 1 ).InnerHTML).trim()
        $latest = "net"+$version.Replace('.','').split(' ')[-1]
        $link = "https://github.com/"+(Invoke-WebRequest -Uri 'https://github.com/microsoft/dotnet/tree/master/releases'  | Select-Object -ExpandProperty Links | Where-Object innerHTML -match $latest.Trim()).href
        $link = (Invoke-WebRequest -Uri $link | Select-Object -ExpandProperty Links | Where-Object innerHTML -match "Download").href
        $file = join-path -Path $env:TMP -ChildPath "Dotnet.exe"
        (New-Object net.webclient).Downloadfile($link, $path)    
        Start-Process $file -ArgumentList "/quiet /norestart"
        Remove-Item $file -Force -ErrorAction SilentlyContinue}
        
    # Desktop Notifications 
        Wait-Job -Name $job2  | Out-Null; 
        Add-Type -AssemblyName System.Windows.Forms
        $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
        $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balmsg.BalloonTipText = $version + ' Installed' 
        $balmsg.BalloonTipTitle = "Winoptimizer"
        $balmsg.Visible = $true
        $balmsg.ShowBalloonTip(20000)
    
        Wait-Job -Name $job1 | Out-Null; 
        Start-Process "$($env:USERPROFILE)\Desktop\"+"Dotnet.exe" -ArgumentList "/quiet /norestart"
        Add-Type -AssemblyName System.Windows.Forms
        $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
        $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balmsg.BalloonTipText = 'NET Framework Version 1,2 & 3.5 Installed' 
        $balmsg.BalloonTipTitle = "Winoptimizer"
        $balmsg.Visible = $true
        $balmsg.ShowBalloonTip(20000)
        