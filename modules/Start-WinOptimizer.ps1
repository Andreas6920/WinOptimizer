# Nuget
    $packageProviders = Get-PackageProvider | Select-Object name
    if(!($packageProviders.name -contains "nuget")){Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null}
    if($packageProviders -contains "nuget"){Import-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null}

# TLS upgrade
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
# Disable Explorer first run
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
    Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1

# install modules
    $modulepath = $env:PSmodulepath.split(";")[1]

    $modules = @(
    "https://raw.githubusercontent.com/Andreas6920/Other/main/modules/backup/upload.psm1"
    "https://raw.githubusercontent.com/Andreas6920/Other/main/Winoptimizer2.psm1"
    "https://raw.githubusercontent.com/Andreas6920/Other/main/modules/backup/Invoke-Antibloat.psm1"
    "https://raw.githubusercontent.com/Andreas6920/Other/main/modules/backup/Invoke-Antihack.psm1"
    "https://raw.githubusercontent.com/Andreas6920/Other/main/modules/backup/Invoke-AppInstall.psm1"
    "https://raw.githubusercontent.com/Andreas6920/Other/main/modules/backup/Restart-Explorer.psm1"
    "https://raw.githubusercontent.com/Andreas6920/Other/main/modules/backup/Start-Input.psm1"
    "https://raw.githubusercontent.com/Andreas6920/Other/main/modules/backup/Stop-Input.psm1"

    )   
    
    foreach ($module in $modules) {
    $file = (split-path $module -Leaf)
    $filename = $file.Replace(".psm1","").Replace(".ps1","").Replace(".psd","")
    $filedestination = "$modulepath/$filename/$file"
    $filesubfolder = split-path $filedestination -Parent
    
    # Create folder, Download module
    If (!(Test-Path $filesubfolder )) {New-Item -ItemType Directory -Path $filesubfolder -Force | Out-Null}
    (New-Object net.webclient).Downloadfile($module, $filedestination)
    
    # Install module
    Import-module -name $filename

    }

    (get-module | where name -eq Winoptimizer2).ExportedCommands
      
