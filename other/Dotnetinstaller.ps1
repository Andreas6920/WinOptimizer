# Microsoft .NET Framework
    
“[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12”
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1


#Version 3.5 (Version 2.0 and 3.0 included)
        If (!(Test-Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing)) {
        New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing | Out-Null}
        Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing -Name RepairContentServerSource -Type DWord -Value 2
        Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" | Out-Null

# Latest
    # Gather download link
        # Get latest release from official microsoft page
        $latest = (Invoke-WebRequest -Uri 'https://dotnet.microsoft.com/en-us/download/dotnet-framework' | Select-Object -ExpandProperty Links | Where-Object innerHTML -match '.Net Framework' | Select-Object -First 1 ).InnerHTML
        write-host "`t- Latest version: $latest" -f DarkGreen
        # Get the specific driver download link from microsoft's official github page
        $link = "https://github.com/"+(Invoke-WebRequest -Uri 'https://github.com/microsoft/dotnet/tree/master/releases'  | Select-Object -ExpandProperty Links | Where-Object innerHTML -match $latest.Trim()).href
        $link = (Invoke-WebRequest -Uri $link | Select-Object -ExpandProperty Links | Where-Object innerHTML -match "Download").href

    # Download
        Invoke-WebRequest -uri $link -OutFile "$($env:TMP)\DotNet.exe"

    # Install
        cd $env:TMP
        ./DotNet.exe /quiet /norestart | Out-Null