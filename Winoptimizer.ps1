# Reinsure admin rights
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {# Relaunch as an elevated process
        $Script = $MyInvocation.MyCommand.Path
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned", "-File `"$Script`""}

# Execution policy
    Set-ExecutionPolicy -Scope Process Unrestricted -Force

# Timestamps for actions
    Function Get-LogDate {
    return (Get-Date -f "[yyyy/MM/dd HH:mm:ss]")}
    Write-Host "$(Get-LogDate)`tINSTALLING:" -ForegroundColor Green

# TLS upgrade
    Write-Host "$(Get-LogDate)`t    - Upgrading TLS connections to TLS 1.2" -ForegroundColor Green
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Install module
    # Create root folder for module
    $BaseFolder = Join-Path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -ChildPath "WinOptimizer"
    if (-not (Test-Path $BaseFolder)) {
        Write-Host "$(Get-LogDate)`t    - Downloading module to $($BaseFolder)" -ForegroundColor Green
        New-Item -ItemType Directory -Path $BaseFolder -Force -ErrorAction SilentlyContinue | Out-Null}

    # Download module
    $modulepath = $env:PSModulePath.Split(";")[1]
    $module = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/functions/WinOptimizer.psm1"
    $file = [System.IO.Path]::GetFileNameWithoutExtension($module)
    $filedestination = Join-Path -Path $modulepath -ChildPath "$file/$file.psm1"
    $filesubfolder = Split-Path -Path $filedestination -Parent

    if (-not (Test-Path $filesubfolder)) {
        New-Item -ItemType Directory -Path $filesubfolder -Force | Out-Null
        Start-Sleep -Seconds 1}

    # Download module
    (New-Object Net.WebClient).DownloadFile($module, $filedestination)

    # Install module
    Import-Module -Name $file

        

 
