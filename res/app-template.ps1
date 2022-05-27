
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name BurntToast -Force
$Logolink = "https://i.ibb.co/sKKh6CP/Microsoft-1.png"
$Logo = "$($env:ProgramData)\Microsoft.png"
(New-Object net.webclient).Downloadfile($logolink, $logo )


if (!(Test-Path "$($env:ProgramData)\chocolatey\choco.exe")) { 
New-BurntToastNotification -Applogo $Logo -Text "Windows", 'Preparing installer..'
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))}
