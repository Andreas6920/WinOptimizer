function Start-WinAppInstall {
    <#param ( [Parameter(Mandatory=$true)]
            [string]$Name,
            [Parameter(Mandatory=$true)]
            [string]$App),
            [Parameter(Mandatory=$false)]
            [switch]$IncludeOffice)#>

        param (
            [Parameter(Mandatory=$true)]
            [string]$Name,
            [Parameter(Mandatory=$true)]
            [string]$App,
            [Parameter(Mandatory=$false)]
            [switch]$IncludeOffice)


    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
    Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
    

    $chocodir = [Environment]::GetFolderPath("CommonApplicationData")
    $chocodir = Join-Path $chocodir -ChildPath "Chocolatey"
    If (!(Test-Path $chocodir)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force;
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Windows notification
    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = 'Installing ' + $Name 
    $balmsg.BalloonTipTitle = "Winoptimizer"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)

    # Install
    choco install $app -y | Out-Null




    if($IncludeOffice){
    
        Write-Host "`tMicrosoft office:" -f Green -nonewline;
        
      
                # Choose version
                    "";
                    Write-Host "`t`tVersion Menu:" -f Green
                    "";
                    Write-Host "`t`t`t - Microsoft 365" -f Yellow
                    Write-Host "`t`t`t - Microsoft Office 2019 Business Retail" -f Yellow
                    Write-Host "`t`t`t - Microsoft Office 2016 Business Retail" -f Yellow
                    "";
                    DO {                     
                        Write-Host "`t`tWhich version would you prefer?" -f Green -nonewline;
                        $answer2 = Read-host " "
                        if("$answer2" -eq "Cancel"){Write-Host "`tSkipping this section.."}                         
                        elseif("$answer2" -match "365")       {$ver = "O365BusinessRetail"; $officename = "Microsoft 365";}
                        elseif("$answer2" -match "2019")      {$ver = "HomeBusiness2019Retail"; $officename = "Microsoft Office 2019";}
                        elseif("$answer2" -match "2016")      {$ver = "HomeBusinessRetail"; $officename = "Microsoft Office 2016"}}
                    While($ver -notin "O365BusinessRetail", "HomeBusiness2019Retail","HomeBusinessRetail")     
              
                # Choose Language
                      "";
                      Write-Host "`t`tLanguage Menu:" -f Green
                      "";
                      Write-Host "`t`t`t- English (United States)" -f Yellow
                      Write-Host "`t`t`t- German" -f Yellow
                      Write-Host "`t`t`t- Spanish" -f Yellow
                      Write-Host "`t`t`t- Danish" -f Yellow
                      Write-Host "`t`t`t- France" -f Yellow
                      Write-Host "`t`t`t- Japanese" -f Yellow
                      Write-Host "`t`t`t- Norwegian" -f Yellow
                      Write-Host "`t`t`t- Russia" -f Yellow
                      Write-Host "`t`t`t- Sweden" -f Yellow
                      "";
                      DO {       
                        Write-Host "`t`tEnter your language from above" -f Green -nonewline;
                        $answer3 = Read-host " "              
                        if("$answer3" -eq "Cancel"){Write-Host "`tSkipping this section.."}                         
                        elseif("$answer3" -match "^Eng")   {$lang = "en-us"}
                        elseif("$answer3" -match "^Ger")   {$lang = "de-de"}
                        elseif("$answer3" -match "^Spa")   {$lang = "es-es"}
                        elseif("$answer3" -match "^Dan")   {$lang = "da-dk"}
                        elseif("$answer3" -match "^Fra")   {$lang = "fr-fr"}
                        elseif("$answer3" -match "^Jap")   {$lang = "ja-jp"}
                        elseif("$answer3" -match "^Nor")   {$lang = "nb-no"}
                        elseif("$answer3" -match "^Rus")   {$lang = "ru-ru"}
                        elseif("$answer3" -match "^Swe")   {$lang = "sv-se"}}
                      While($lang -notin "en-us", "de-de","es-es","da-dk","fr-fr","ja-jp","nb-no","ru-ru","sv-se")

                    # Windows notification 1
                        Add-Type -AssemblyName System.Windows.Forms
                        $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
                        $path = (Get-Process -id $pid).Path
                        $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
                        $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
                        $balmsg.BalloonTipText = 'Installing ' + $officename + '...'
                        $balmsg.BalloonTipTitle = "Microsoft Office"
                        $balmsg.Visible = $true
                        $balmsg.ShowBalloonTip(20000)
                    
                    # Installation
                        Get-AppxPackage | Where-Object Name -Match "Microsoft.MicrosoftOfficeHub|Microsoft.Office.OneNote" | Remove-AppxPackage;
                        choco install microsoft-office-deployment /64bit /Product $ver /language REPLACE-ME-LANGUAGE -y
                        
                    
                    # Windows notification 2
                        Add-Type -AssemblyName System.Windows.Forms
                        $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
                        $path = (Get-Process -id $pid).Path
                        $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
                        $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
                        $balmsg.BalloonTipText = 'Installation complete!'
                        $balmsg.BalloonTipTitle = "Microsoft Office"
                        $balmsg.Visible = $true
                        $balmsg.ShowBalloonTip(20000)    
                        
                        }


# Start app installation              
    Start-Process Powershell -argument "-Ep bypass -Windowstyle hidden -file `"""$($env:ProgramData)\Winoptimizer\Invoke-AppInstall.ps1""`""

                    #create update file
                    Write-Host "`t`t- Downloading updating script." -f Yellow
                    $filepath = "$env:ProgramData\chocolatey\app-updater.ps1"
                    Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/app-updater/app-updater.ps1" -OutFile $filepath -UseBasicParsing
                    
                    # Create scheduled job
                    Write-Host "`t`t- scheduling update routine." -f Yellow
                    $name = 'winoptimizer-app-Updater'
                    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-nop -W hidden -noni -ep bypass -file $filepath"
                    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"-LogonType ServiceAccount -RunLevel Highest
                    $trigger= New-ScheduledTaskTrigger -At 12:05 -Daily
                    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -RunOnlyIfIdle -DontStopOnIdleEnd -IdleDuration 00:05:00 -IdleWaitTimeout 03:00:00

                    Register-ScheduledTask -TaskName $Name -Taskpath "\Microsoft\Windows\Winoptimizer\" -Settings $settings -Principal $principal -Action $action -Trigger $trigger -Force | Out-Null

}}