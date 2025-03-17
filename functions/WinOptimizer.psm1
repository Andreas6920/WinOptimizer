# Prepare

        # TLS upgrade
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Write-host "Loading" -NoNewline

        # Disable Explorer first run
            $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main"
            If (!(Test-Path $RegistryKey)) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
            if(!(Get-Item "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\" | ? Property -EQ "DisableFirstRunCustomize")){Write-host "." -NoNewline; Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1}
        
        # Install Nuget
            if(!(test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208")){
                $ProgressPreference = "SilentlyContinue"; Start-Sleep -S 1; Write-host "." -NoNewline;  
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null}
        
        # Create Base Folder
            $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
            if(!(test-path $BaseFolder)){Write-host "." -NoNewline; New-Item -itemtype Directory -Path $BaseFolder -ErrorAction SilentlyContinue | Out-Null }        

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

Function Get-LogDate {
        return (Get-Date -f "[yyyy/MM/dd HH:mm:ss]")}

Function Start-Menu {
            <# When you're choosing the UI version of this script, the menu options will grey out if the exact script
            has aldready been ran on the system.. Yep, spent way to much time on this feature.#>
            param (
                [Parameter(Mandatory=$true)]
                [string]$Name,
                [Parameter(Mandatory=$true)]
                [string]$Number,
                [Parameter(Mandatory=$false)]
                [string]$Rename)

            $Base = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
            $path = Join-Path -Path $Base -Childpath "$Name.ps1"
            $file = "$Name.ps1"
            $filehash = (Get-FileHash $path).Hash
            $reg_install = "HKLM:\Software\WinOptimizer"
            $reghash = (get-ItemProperty -Path $reg_install -Name $file).$file

            if($filehash -eq $reghash){$color = "Gray"}
            elseif($filehash -ne $reghash){$color = "White"}
            if($reghash -eq "0"){$color = "White"}
            
            if($rename) {   Write-Host "`t[$number] - $rename" -ForegroundColor $color  }
            else {          Write-Host "`t[$number] - $name" -ForegroundColor $color    }}

Function Start-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($false)
    }

Function Stop-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($true)
    }


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


Function Add-Hash {
        <# When you're choosing the UI version of this script, the menu options will grey out if the exact script
        has aldready been ran on the system.. Yep, spent way to much time on this feature.#>
        param (
            [Parameter(Mandatory=$true)]
            [string]$Name)

        $Base = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
        $path = Join-Path -Path $Base -Childpath "$Name.ps1"
        $file = "$Name.ps1"
        $filehash = (Get-FileHash $path).Hash
        $reg_install = "HKLM:\Software\WinOptimizer"
         #$reghash = (get-ItemProperty -Path $reg_install -Name $file).$file

        Set-ItemProperty -Path $reg_install -Name $file -Type String -Value $filehash        
        
    }



## Scripts

            $scripts = @(   "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinAntiBloat.ps1"
                            "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinSecurity.ps1"
                            "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Start-WinOptimizer.ps1"
                            "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/scripts/Install-App.ps1"
                            )
            Foreach ($script in $scripts) {
                # Download and install functions
                    $filename = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $url -Leaf))
                    $filedestination = join-path $BaseFolder -Childpath $filename
                        if(!(test-path $Filepath)){
                                New-Item -Path $Filepath -Force | Out-Null
                                Invoke-RestMethod -uri $script -OutFile $filedestination
                                Import-module -name $filedestination; Add-Hash -Name $filename
                                Write-Host "." -NoNewline}
                # Creating Missing Regpath
                    $reg_install = "HKLM:\Software\WinOptimizer"
                    If(!(Test-Path $reg_install)) {New-Item -Path $reg_install -Force | Out-Null;}
                # Creating Missing Regkeys
                    if (!((Get-Item -Path $reg_install).Property -match $filename)){Set-ItemProperty -Path $reg_install -Name $filename -Type String -Value 0}}





    <#

        $win_antibloat = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_antibloat.ps1"
        $win_security = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_security.ps1"
        $win_settings = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_settings.ps1"
        $app_installer = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app_install.ps1"
        $Basefolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"

    
    Function Start-WinAntiBloat {
             $Link = $win_antibloat
            $Filepath = Join-path -Path $basefolder -ChildPath "win_antibloat.ps1"
            if(!(test-path $Filepath)){New-Item -Path $Filepath -Force | Out-Null}
            Invoke-WebRequest -Uri $Link -OutFile $Filepath -UseBasicParsing
            Import-Module $Filepath; Add-Hash -Name "win_antibloat"
           

    Function Start-WinSecurity {
            $Link = $win_security
            $Filepath = Join-path -Path $basefolder -ChildPath "win_security.ps1"
            if(!(test-path $Filepath)){New-Item -Path $Filepath -Force | Out-Null}
        Invoke-WebRequest -Uri $Link -OutFile $Filepath -UseBasicParsing
        Import-Module $Filepath; Add-Hash -Name "win_security"}

    Function Start-WinSettings {
            $Link = $win_settings
            $Filepath = Join-path -Path $basefolder -ChildPath "win_settings.ps1"
            if(!(test-path $Filepath)){New-Item -Path $Filepath -Force | Out-Null}
        Invoke-WebRequest -Uri $Link -OutFile $Filepath -UseBasicParsing
        Import-Module $Filepath; Add-Hash -Name "win_settings"}

    Function Install-App {
            $Link = $app_installer
            $Filepath = Join-path -Path $basefolder -ChildPath "app_install.ps1"
            if(!(test-path $Filepath)){New-Item -Path $Filepath -Force | Out-Null}
        Invoke-WebRequest -Uri $Link -OutFile $Filepath -UseBasicParsing
        Import-Module $Filepath; Add-Hash -Name "install_app"}

#>


Function Start-WinOptimizer {

$intro = 
"
 _       ___       ____        __  _           _                
| |     / (_)___  / __ \____  / /_(_)___ ___  (_)___  ___  _____
| | /| / / / __ \/ / / / __ \/ __/ / __ `__  \/ /_  / / _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / /_/ / / / / / / / / /_/  __/ /    
|__/|__/_/_/ /_/\____/ .___/\__/_/_/ /_/ /_/_/ /___/\___/_/     
                    /_/                                         
Version 3.0
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "


# Start Menu

do {
    Set-Location (Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer")
    Clear-Host
    Write-Host $intro -f Yellow 
    Write-Host "`t[1] - All"
    Start-Menu -Name "win_antibloat" -Number "2" -Rename "Clean Windows"
    Start-Menu -Name "win_security" -Number "3" -Rename "Secure Windows"
    Start-Menu -Name "win_settings" -Number "4" -Rename "Configure Windows"
    Write-Host "`t[5] - Install Applications"
    Write-Host ""
    Write-Host "`t[0] - Quit"
    Write-Host ""
    Write-Host "`nOption: " -f Yellow -nonewline; ;

        $option = Read-Host
        Switch ($option) { 
            0 { exit }
            1 { Start-WinAntiBloat; Start-WinSecurity; Start-WinSettings; Start-WinOptimizer}
            2 { Start-WinAntiBloat; Start-WinOptimizer; }
            3 { Start-WinSecurity; Start-WinOptimizer; }
            4 { Start-WinSettings; Start-WinOptimizer; }
            5 { Install-App; Start-WinOptimizer;}
            Default {  Write-Host "INVALID OPTION. TRY AGAIN.." -f red; Start-Sleep -s 2; Start-WinOptimizer } 
        }
}

while ($option -ne 5 )




}