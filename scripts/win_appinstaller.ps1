# Disable Explorer first run
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main"
If(!(Get-Item $RegistryPath | ? Property -EQ "DisableFirstRunCustomize")){Write-host "`t- Disable First Run Internet Explorer.."; Set-ItemProperty -Path  $RegistryPath -Name "DisableFirstRunCustomize" -Value 1}

# Path 
$rootpath = [Environment]::GetFolderPath("CommonApplicationData")
$applicationpath = Join-path -Path $rootpath -Childpath "WinOptimizer\AppInstaller"
if(!(Test-Path $applicationpath)){Write-host "`t- Creating folder.."; New-Item -ItemType Directory -Path $applicationpath -Force | Out-Null}

# File
$filepath = Join-path -Path $rootpath -Childpath "WinOptimizer\AppInstaller\app-installer.ps1"
New-Item -Path $filepath -Force | Out-Null

# Install Chocolatey -> File
$WebResponse = Invoke-WebRequest -Uri "https://chocolatey.org/install"
$chococode = ($WebResponse.AllElements | ? {$_.Class -eq "form-control text-bg-theme-elevation-1 user-select-all border-start-0 ps-1"}).Value
if(!($chococode)){$chococode = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"}
Add-Content -Encoding UTF8 -Value $chococode -Path $filepath

