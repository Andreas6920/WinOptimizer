<#
    Next up:
        -  Menu change color if module runned.
            White if not used, orange if interupted, gray if used.
        - Module convert (Menu = script, functions = module)
            Import-Module C:\.. -Function remove_bloat

#>
# Check for admin rights
    $admin_permissions_check = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $admin_permissions_check = $admin_permissions_check.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin_permissions_check) {

# Prepare
    Write-host "Loading" -NoNewline
    # Nuget
        $ProgressPreference = "SilentlyContinue" # hide progressbar
        $packageProviders = Get-PackageProvider | Select-Object name
        if(!($packageProviders.name -contains "nuget")){Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null}
        if($packageProviders -contains "nuget"){Import-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force -Scope CurrentUser | Out-Null}
        $ProgressPreference = "Continue" #unhide progressbar
    # TLS upgrade
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # Disable Explorer first run
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
        Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
        Write-host "." -NoNewline
# Install modules

    $modulepath = $env:PSmodulepath.split(";")[1]
    $modules = @(
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Start-WinAntiBloat.psm1"
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Start-WinAntiHack.psm1"
    #"https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Start-WinAppInstall.psm1"
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Start-WinSettings.psm1"
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Start-WinOptimizer.psm1"
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Add-Reg.psm1"
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Restart-Explorer.psm1"
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Start-Input.psm1"
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/modules/Stop-Input.psm1")

    Foreach ($module in $modules) {
    # prepare folder
        $file = (split-path $module -Leaf)
        $filename = $file.Replace(".psm1","").Replace(".ps1","").Replace(".psd","")
        $filedestination = "$modulepath/$filename/$file"
        $filesubfolder = split-path $filedestination -Parent
        If (!(Test-Path $filesubfolder )) {New-Item -ItemType Directory -Path $filesubfolder -Force | Out-Null; Start-Sleep -S 1}
    # Download module
        (New-Object net.webclient).Downloadfile($module, $filedestination)
    # Install module
        if (Get-Module -ListAvailable -Name $filename){ Import-module -name $filename; Write-host "." -NoNewline}
        #else {write-host "!"}
    }
        
    write-host ""
    start-sleep -s 10
# Front end begins here
$intro = 
"
 _       ___       ____        __  _           _                
| |     / (_)___  / __ \____  / /_(_)___ ___  (_)___  ___  _____
| | /| / / / __ \/ / / / __ \/ __/ / __ `__  \/ /_  / / _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / /_/ / / / / / / / / /_/  __/ /    
|__/|__/_/_/ /_/\____/ .___/\__/_/_/ /_/ /_/_/ /___/\___/_/     
                    /_/                                         
Version 2.9.3
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "
do {
    Write-Host $intro -f Yellow 
    Write-Host "Please select one of the following options:" -f Yellow
    Write-Host ""; Write-Host "";
    Write-Host "`t[1] - All"
    Write-Host "`t[2] - Bloatware optimizer"
    Write-Host "`t[3] - Privacy And security optimizer"
    Write-Host "`t[4] - Windows settings optimizer"
    Write-Host "`t[5] - App installer"
    "";
    Write-Host "`t[0] - Exit"
    Write-Host ""; Write-Host "";
    Write-Host "Option: " -f Yellow -nonewline; ;
    $option = Read-Host
    Switch ($option) { 
        0 { exit }
        1 { Start-WinAntiBloat; Start-WinAntihack; Start-WinSettings; Start-WinAppInstall }
        2 { Start-WinAntiBloat }
        3 { Start-WinAntihack }
        4 { Start-WinSettings }
        5 { Start-WinAppInstall }
        Default { } 
    }
        
}
while ($option -ne 5 )

} 
else {  Write-host ""
        Write-host "`t" -nonewline
        Write-host "This PowerShell windows is not opened as administrator" -b red -f white
        Write-host "`t" -nonewline
        Write-host 'Please close this window and choose "Windows PowerShell (Admin)"'  -b red -f white
        Write-host ""
        Write-host ""}