# Reinsure admin rights
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {# Relaunch as an elevated process
        $Script = $MyInvocation.MyCommand.Path
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned", "-File `"$Script`""}

# Execution policy
    Set-ExecutionPolicy -Scope Process Unrestricted -Force
    
# TLS upgrade
    Clear-Host
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-host "Loading" -NoNewline

# Install module
    $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
    if(!(test-path $BaseFolder)){Write-host "." -NoNewline; new-item -itemtype Directory -Path $BaseFolder -Force -ErrorAction SilentlyContinue | Out-Null }

    $modulepath = $env:PSmodulepath.split(";")[1]
    $module = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/functions/WinOptimizer.psm1"
    $file = (split-path $module -Leaf)
    $filename = $file.Replace(".psm1","").Replace(".ps1","").Replace(".psd","")
    $filedestination = "$modulepath/$filename/$file"
    $filesubfolder = split-path $filedestination -Parent
    If (!(Test-Path $filesubfolder )) {New-Item -ItemType "Directory" -Path $filesubfolder -Force | Out-Null; Start-Sleep -S 1}
    # Download module
    (New-Object net.webclient).Downloadfile($module, $filedestination)
    # Install module
    Import-module -name $filename
        

 
