# Prepare

        # Timestamps for actions
            Function Get-LogDate {
            return (Get-Date -f "[yyyy/MM/dd HH:mm:ss]")}

        # Disable Explorer first run
            $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main"
            If (!(Test-Path $RegistryKey)) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
            if(!(Get-Item "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\" | ? Property -EQ "DisableFirstRunCustomize")){Write-Host "$(Get-LogDate)`t- Disabling explorer first run" -f Green; Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1}
        
        # Install Nuget
            if(!(test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208")){
                Write-Host "$(Get-LogDate)`t- Installing Nuget" -f Green
                $ProgressPreference = "SilentlyContinue"; 
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null;
                Start-Sleep -S 1;}
        
        # Create Base Folder
            Write-Host "$(Get-LogDate)`t- Setting up root folder" -f Green
            $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
            if(!(test-path $BaseFolder)){New-Item -itemtype Directory -Path $BaseFolder -ErrorAction SilentlyContinue | Out-Null }        

Write-Host "$(Get-LogDate)`t- Installing modules" -f Green -nonewline


Function Add-Reg {
 
         param (
             [Parameter(Mandatory=$true)]
             [string]$Path,
             [Parameter(Mandatory=$true)]
             [string]$Name,
             [Parameter(Mandatory=$true)]
             [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword',' Unknown')]
             [String]$Type,
             [Parameter(Mandatory=$true)]
             [string]$Value
         )
 
            # If base reg exists
            If (!(Test-Path $path)){New-Item -Path $path -Force | Out-Null}; 
        
            # If reg key exists
            if((Get-Item -Path $path).Property -match $name){
            # If value is not the same, change it
                if ((Get-ItemPropertyValue $path -Name $name) -ne $Value){Set-ItemProperty -Path $path -Name $Name -Value $Value -Type $Type -Force | Out-Null}}
        
            # If reg key does not exist, create it
            else{Set-ItemProperty -Path $path -Name $Name -Value $Value -Type $Type -Force | Out-Null}
            }

Function Restart-Explorer {
            <# When explorer restarts with the regular stop-process function, the active PowerShell loses focus,
            which means you'll have to click on the window in order to enter your input. here's the hotfix. #>
            if(Get-Process -Name "Explorer" -ErrorAction SilentlyContinue){
            Stop-Process -Name "Explorer" -Force -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 2
            if(!(Get-Process -Name Explorer)){Start-Process Explorer -ErrorAction SilentlyContinue}}
            #taskkill /IM explorer.exe /F | Out-Null -ErrorAction SilentlyContinue
            #start explorer | Out-Null
            $windowname = $Host.UI.RawUI.WindowTitle
            Add-Type -AssemblyName Microsoft.VisualBasic
            [Microsoft.VisualBasic.Interaction]::AppActivate($windowname)}
            Write-Host "." -f Green -nonewline

Function Start-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($false)
    }
Write-Host "." -f Green -nonewline

Function Stop-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($true)
    }
Write-Host "." -f Green -nonewline


## Other bigger modules
            
    $modules = @(   "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinAntiBloat.ps1"
                    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinSecurity.ps1"
                    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinOptimizer.ps1"
                    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Install-App.ps1"
                    )
    
    Foreach ($module in $modules) {
        # Download and install functions
            $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
                if(!(test-path $BaseFolder)){Write-host "." -NoNewline; New-Item -itemtype Directory -Path $BaseFolder -ErrorAction SilentlyContinue | Out-Null }        
            $filename = Split-Path $module -Leaf
            $modulename = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $module -Leaf))
            $filedestination = join-path $BaseFolder -Childpath $filename
                if(!(test-path $filedestination)){
                        Invoke-RestMethod -uri $module -OutFile $filedestination
                        Import-module -name $filedestination;
                        Write-Host "." -f Green -nonewline}}
                        Write-Host "." -f Green
        
Function Start-WinOptimizer {        
$intro = 
"
 _       ___       ____        __  _           _                
| |     / (_)___  / __ \____  / /_(_)___ ___  (_)___  ___  _____
| | /| / / / __ \/ / / / __ \/ __/ / __ `__  \/ /_  / / _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / /_/ / / / / / / / / /_/  __/ /    
|__/|__/_/_/ /_/\____/ .___/\__/_/_/ /_/ /_/_/ /___/\___/_/     
                    /_/                                         
Version 4.0
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "


# Start Menu

do {
    Clear-Host
    Write-Host $intro -f Yellow 
    Write-Host "`t[1]`tAll"
    Write-Host "`t[2]`tStart-AntiBloat"
    Write-Host "`t[3]`tStart-WinSecurity"
    Write-Host "`t[4]`tStart-WinSettings"
    Write-Host "`t[5]`tInstall-App"
    Write-Host ""
    Write-Host "`t[0] - Quit"
    Write-Host ""
    Write-Host "`nOption: " -f Yellow -nonewline; ;

        $option = Read-Host
        Switch ($option) { 
            0 { exit }
            1 { Start-WinAntiBloat; Start-WinSecurity; Start-WinSettings; Start-WinOptimizer}
            2 { Start-WinAntiBloat; Start-WinOptimizer; }
            3 { Start-WinSecurity;}
            4 { Start-WinSettings;}
            5 { Install-App;}
            Default {  Write-Host "INVALID OPTION. TRY AGAIN.." -f red; Start-Sleep -s 2; Start-WinOptimizer } 
        }
}

while ($option -ne 5 )
}




