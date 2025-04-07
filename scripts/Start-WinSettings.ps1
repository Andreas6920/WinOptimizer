﻿Function Start-WinSettings {
Write-Host "`n$(Get-LogDate)`tENHANCE WINDOWS Settings" -f Green

    # Windows settings
        Write-Host "$(Get-LogDate)`t    COnfigure Windows:" -f Green


    # Disable LockScreen ScreenSaver? To prevent missing first character
        Write-Host "$(Get-LogDate)`t        - Disabling screensaver sleep to prevent missing keystrokes" -f Yellow
        Add-Reg -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "Personalization" -Type "DWORD" -Value "1"
    
    # Taskbar: Hide Searchbox
        Write-Host "$(Get-LogDate)`t        - Taskbar: Hide the searchbox" -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type "DWORD" -Value "0"
        Restart-Explorer
        
    # Taskbar: Hide task view button
        Write-Host "$(Get-LogDate)`t        - Taskbar: Hide task view" -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView" -Name "ShowTaskViewButton" -Type "DWORD" -Value "0"
        Restart-Explorer

    # Show file extensions
        Write-Host "$(Get-LogDate)`t        - Show file extensions" -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type "DWORD" -Value "0"
            
    # Show hidden files
        Write-Host "$(Get-LogDate)`t        - Show hidden files" -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type "DWORD" -Value "1"
        
    # Change Explorer to "This PC"
        Write-Host "$(Get-LogDate)`t        - Change explorer to 'This PC' instead of 'Documents'" -f Yellow
        Add-Reg -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type "DWORD" -Value "1"
        
    # Start Menu: Disable Bing Search Results
        Write-Host "$(Get-LogDate)`t        - Disabling bing search results in windows search menu" -f Yellow
        Add-Reg -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type "DWORD" -Value "0"

    # Remove 3D objects
        Write-Host "$(Get-LogDate)`t        - Disabling 3D Objects app" -f Yellow
        $3Dlocation32bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
        $3Dlocation64bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A"
        If((test-path $3Dlocation32bit )){remove-item $3Dlocation32bit}
        If((test-path $3Dlocation64bit )){remove-item $3Dlocation64bit}

    # Enable Windows Dark Mode
        Do {
            Write-Host "`t- Enable Dark Mode (y/n)" -f Green -nonewline;
            $answer = Read-Host " " 
            Switch ($answer) { 
                Y {
                    Write-Host "`t`t- YES. Enabling Dark Mode" -f Green
                    $keys = "AppsUseLightTheme","SystemUsesLightTheme"; 
                    $keys | % {Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "$_" -Type "DWORD" -Value "0"}
                }
                N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
            }   
        } While ($answer -notin "y", "n")               

    # Install Hyper-V
        Do {
            Write-Host "`t- Install Hyper-V? (y/n)" -f Green -nonewline;
            $answer = Read-Host " " 
            Switch ($answer) { 
                Y {
                    Write-Host "`t`t- YES. Installing Hyper-V.. (this may take a while)" -f Green
                    $ProgressPreference = "SilentlyContinue" #hide progressbar
                    if (((Get-WmiObject -class Win32_OperatingSystem).Caption) -match "Home"){$dst = "$env:TMP\install-hyper-v"
                        Write-Host "`t`t- Windows Home detected, additional script is needed!" -f Green
                        $link = "https://gist.githubusercontent.com/samuel-fonseca/662a620ae32aca254ea7730be5ff7145/raw/a1de2537d5b0613e29c9ca3b9bc0ec67ff1e29a2/Hyper-V-Enabler.bat"
                        $file = "$dir\"+(Split-Path $link -Leaf)
                        (New-Object net.webclient).Downloadfile("$link", "$file"); 
                        Start-Sleep -s 3; 
                        start cmd -Verb RunAs -ArgumentList "/c","$dst/$file" -wait}
                    elseIf ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*"){Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null}
                    Else { Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null }
                    $ProgressPreference = "Continue" #unhide progressbar
                    Write-Host "`t`t- Installation complete. Restart PC to take effect." -f Green;
                }
                N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
            }   
        } While ($answer -notin "y", "n")  

    # Install Linux Sub-system
        Do {
            Write-Host "`t- Install Linux Sub-system? (y/n)" -f Greem -nonewline;
            $answer = Read-Host " " 
            Switch ($answer) { 
                Y {
                    Write-Host "`t`t- YES. Installing Linux sub-system.. (this may take a while)" -f Green
                    $ProgressPreference = "SilentlyContinue" #hide progressbar
                    
                    # Enable Linux Sub-system Feature
                    If ([System.Environment]::OSVersion.Version.Build -ge 14393) {
                    $keys = "AllowDevelopmentWithoutDevLicense","AllowAllTrustedApps"; 
                    $keys | % {Add-Reg -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "$_" -Type "DWORD" -Value "1"}}
                    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null 
                    
                    # Download ubuntu
                    $link = "https://wsldownload.azureedge.net/Ubuntu_2004.2020.424.0_x64.appx"
                    $file = "$dir\"+(Split-Path $link -Leaf)
                    (New-Object net.webclient).Downloadfile("$link", "$file")

                    # Install Ubuntu
                    Add-AppxPackage $file; Start-Sleep -S 3; Remove-item $file
                    $ProgressPreference = "Continue" #unhide progressbar
                    Start-Sleep -S 3;
                    
                    
                    Write-Host "`t`t- Installation complete." -f Green;
                }
                N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
            }   
        } While ($answer -notin "y", "n")         
    
    #End of function
    Write-Host "`tWindows customizer completed. Your system is now customized." -f Green
    Start-Sleep 10}