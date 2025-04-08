Function Start-WinSettings {

    # Ensure admin rights
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
		# Relaunch as an elevated process
		$Script = $MyInvocation.MyCommand.Path
		Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned", "-File `"$Script`""}

    # Tjek om systemet er Windows 11 baseret eller 10
        $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        if([int]$BuildNumber -ge 22000){$ThisIsWindows11 = $True; $ThisIsWindows10 = $False;}
        else{$ThisIsWindows11 = $False; $ThisIsWindows10 = $True;}
            if($ThisIsWindows10){$SystemVersion = "Windows 10"}
            if($ThisIsWindows11){$SystemVersion = "Windows 11"}

# Start
Write-Host "`n$(Get-LogDate)`tENHANCE WINDOWS SETTINGS, $($SystemVersion)" -f Green
Write-Host "$(Get-LogDate)`t    Configure Windows:" -f Green

    # Disable LockScreen ScreenSaver? To prevent missing first character
    Write-Host "$(Get-LogDate)`t        - Disabling screensaver sleep to prevent missing keystrokes" -f Yellow
    Add-Reg -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "Personalization" -Type "DWORD" -Value "1"

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


        if($ThisIsWindows10){

            # Taskbar: Hide task view button
                Write-Host "$(Get-LogDate)`t        - Taskbar: Hide task view" -f Yellow
                Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView" -Name "ShowTaskViewButton" -Type "DWORD" -Value "0"

            # Remove 3D objects
                Write-Host "$(Get-LogDate)`t        - Disabling 3D Objects app" -f Yellow
                $3Dlocation32bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
                $3Dlocation64bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A"
                If((test-path $3Dlocation32bit )){remove-item $3Dlocation32bit}
                If((test-path $3Dlocation64bit )){remove-item $3Dlocation64bit}
        }

        if($ThisIsWindows11){
            # Remove 3D objects
            Write-Host "$(Get-LogDate)`t        - Move taskbar icons to left" -f Yellow
            Add-Reg -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type "DWord" -Value "0"
        }


    # Enable Windows Dark Mode
        Do {
            Write-Host "`t- Enable Dark Mode (y/n)" -f Green -nonewline;
            $answer = Read-Host " " 
            Switch ($answer) { 
                Y {
                    Write-Host "`t`t- YES. Enabling Dark Mode" -f Green
                    $keys = "AppsUseLightTheme","SystemUsesLightTheme"; 
                    $keys | % {Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "$_" -Type "DWORD" -Value "0"}
                    Restart-Explorer
                }
                N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
            }   
        } While ($answer -notin "y", "n")                        
    
    #End of function
    Write-Host "`tWindows customizer completed. Your system is now customized." -f Green
    Start-Sleep 10}