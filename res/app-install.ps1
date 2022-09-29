function appinstall {
            param ( [Parameter(Mandatory=$true)]
                    [string]$Name,
                    [Parameter(Mandatory=$true)]
                    [string]$App)
        
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
            Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
            
            $code = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
            $appinstall = "$($env:ProgramData)\Winoptimizer\appinstall.ps1"
        
            if(!(test-path $appinstall)){new-item -ItemType Directory ($appinstall | Split-Path) -ea ignore | out-null; New-item $appinstall -ea ignore | out-null;}
            if(!((get-content $appinstall) -notmatch "https://community.chocolatey.org/install.ps1")){Set-content -Encoding UTF8 -Value $code -Path $appinstall}
        
            Add-content -Encoding UTF8 -Value (invoke-webrequest "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/app-template.ps1").Content.replace('REPLACE-ME-NAME', $Name).replace('REPLACE-ME-APP', $App) -Path $appinstall}
