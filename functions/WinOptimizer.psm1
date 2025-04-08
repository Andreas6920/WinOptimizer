# Prepare

        # Timestamps for actions
            Function Get-LogDate {
            return (Get-Date -f "[yyyy/MM/dd HH:mm:ss]")}

        # Disable Explorer first run
            $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main"
            If (!(Test-Path $RegistryKey)) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
            if(!(Get-Item "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\" | ? Property -EQ "DisableFirstRunCustomize")){ Write-Host "$(Get-LogDate)`t        - Disabling explorer first run." -ForegroundColor Yellow; Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1}
        
        # Install Nuget
            if(!(test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208")){
                Write-Host "$(Get-LogDate)`t        - Installing Nuget" -ForegroundColor Yellow
                $ProgressPreference = "SilentlyContinue"; 
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null;
                Start-Sleep -S 1;}
        
        # Create Base Folder
            Write-Host "$(Get-LogDate)`t        - Setting up root folder" -ForegroundColor Yellow
                $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
                if(!(test-path $BaseFolder)){New-Item -itemtype Directory -Path $BaseFolder -ErrorAction SilentlyContinue | Out-Null }        

        Write-Host "$(Get-LogDate)`t        - Installing functions" -ForegroundColor Yellow -nonewline

        Function Add-Reg {
            param (
                [Parameter(Mandatory=$true)]
                [string]$Path,
                [Parameter(Mandatory=$true)]
                [string]$Name,
                [Parameter(Mandatory=$true)]
                [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword', 'Unknown')]
                [string]$Type,
                [Parameter(Mandatory=$true)]
                [string]$Value    )
        
            try {
                if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        
                $CurrentValue = $null
                if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {$CurrentValue = (Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue)}
        
                if ($CurrentValue -ne $Value) {
                    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
                    Write-Host "$(Get-LogDate)`t            - Registry '$Name' sat til '$Value'." -ForegroundColor Yellow} 
                else {Write-Host "$(Get-LogDate)`t            - Registry '$Name' er allerede sat til '$Value'" -ForegroundColor Yellow}}

            catch {
                if ($_.Exception.GetType().Name -eq "UnauthorizedAccessException") {
                    # Undertrykker denne type fejl
                    Write-Host "$(Get-LogDate)`t            - Adgang nægtet til '$Name'. Springer over." -ForegroundColor DarkGray}
                else {Write-Host "Fejl - Kan ikke modificere '$Name': $_" -ForegroundColor Red}}
        }
        

Function Restart-Explorer {
            <# When explorer restarts with the regular stop-process function, the active PowerShell loses focus,
            which means you'll have to click on the window in order to enter your input. here's the hotfix. #>
            if(Get-Process -Name "Explorer" -ErrorAction SilentlyContinue){
            Stop-Process -Name "Explorer" -Force -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 2
            if(!(Get-Process -Name Explorer)){Start-Process Explorer -ErrorAction SilentlyContinue}}
            $windowname = $Host.UI.RawUI.WindowTitle
            Add-Type -AssemblyName Microsoft.VisualBasic
            [Microsoft.VisualBasic.Interaction]::AppActivate($windowname)}
            Write-Host "." -ForegroundColor Yellow -nonewline

Function Start-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($false)
    }
Write-Host "." -ForegroundColor Yellow -nonewline

Function Stop-Input{
    $WWcode = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($true)
    }
Write-Host "." -ForegroundColor Yellow -nonewline


## Other bigger modules

$ModulePath = $env:PSModulePath.Split(";")[1]
$ScriptFolder = Join-Path -Path $ModulePath -ChildPath "WinOptimizer\Scripts"

# Opret mappe
if (-not (Test-Path $ScriptFolder)) { New-Item -ItemType Directory -Path $ScriptFolder -Force | Out-Null }

$ScriptURLs = @(
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinAntiBloat.ps1",
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinSecurity.ps1",
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinSettings.ps1",
    "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Install-App.ps1"
)

Foreach ($ScriptURL in $ScriptURLs) {
    # Download and save script files
    $ScriptName = Split-Path $ScriptURL -Leaf
    $ScriptLocation = Join-Path -Path $ScriptFolder -ChildPath $ScriptName

    try {   (New-Object Net.WebClient).DownloadFile($ScriptURL, $ScriptLocation)
        
            # Kør scriptet (dot-sourcing for at importere funktioner hvis der er nogen)
            . $ScriptLocation
            Write-Host "." -ForegroundColor Yellow -NoNewline}
    
    catch { Write-Host "Failed to download or import $ScriptName - $_" -ForegroundColor Red }
}



Write-Host "." -ForegroundColor Yellow
        
Function Start-WinOptimizer {        
$intro = 
"
 _       ___       ____        __  _           _                
| |     / (_)___  / __ \____  / /_(_)___ ___  (_)___  ___  _____
| | /| / / / __ \/ / / / __ \/ __/ / __ `__  \/ /_  / / _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / /_/ / / / / / / / / /_/  __/ /    
|__/|__/_/_/ /_/\____/ .___/\__/_/_/ /_/ /_/_/ /___/\___/_/     
                    /_/                                         
Version 5.0
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
            1 { Start-WinAntiBloat; Start-WinOptimizer; Start-WinSecurity; Start-WinSettings }
            2 { Start-WinAntiBloat }
            3 { Start-WinSecurity }
            4 { Start-WinSettings }
            5 { Install-App }
            Default {  Write-Host "INVALID OPTION. TRY AGAIN.." -f red; Start-Sleep -s 2; Start-WinOptimizer } 
        }
}

while ($option -ne 5 )
}




