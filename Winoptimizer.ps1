# Ensure Admin Rights
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {# Relaunch as an elevated process
        $Script = $MyInvocation.MyCommand.Path
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned", "-File `"$Script`""}

# Execution policy
    Set-ExecutionPolicy -Scope Process Unrestricted -Force

# Timestamps for actions
    Function Get-LogDate {
    return (Get-Date -f "[yyyy/MM/dd HH:mm:ss]")}
    Write-Host "$(Get-LogDate)`tSYSTEM INITIALIZATION" -ForegroundColor Green

# TLS upgrade
    Write-Host "$(Get-LogDate)`t    - Upgrading TLS connections to TLS 1.2" -ForegroundColor Green
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Installér modul
$ModuleUrl = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/functions/WinOptimizer.psm1"
$ModuleName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $ModuleUrl -Leaf))
$ModulePath = $env:PSModulePath.Split(";")[1]
$ModuleFolder = Join-Path -Path $ModulePath -ChildPath $ModuleName
$ModuleLocation = Join-Path -Path $Modulefolder -ChildPath (Split-Path $ModuleUrl -Leaf)

    # Opretter modulmappen, hvis den ikke eksisterer
    if (-not (Test-Path $ModuleFolder)) {
        New-Item -ItemType Directory -Path $ModuleFolder -Force | Out-Null}

    # Download modulet
    Write-Host "$(Get-LogDate)`t    - Henter modulet til $ModulePath" -ForegroundColor Green
    (New-Object Net.WebClient).DownloadFile($ModuleUrl, $ModuleLocation)
    
    # Kontroller, om filen er blevet downloadet korrekt
    if (Test-Path $ModuleLocation) {Write-Host "$(Get-LogDate)`t    - Module downloaded successfully." -ForegroundColor Green

        # Installer og importer modulet
        try {
            Import-Module -Name $ModuleName -Force -ErrorAction Stop
            Write-Host "$(Get-LogDate)`t    - Modulet hentet." -ForegroundColor Green}
        catch {
            Write-Host "$(Get-LogDate)`t    - Failed to import module: $_" -ForegroundColor Red}} 

    else {  Write-Host "$(Get-LogDate)`t    - Module download failed." -ForegroundColor Red }
