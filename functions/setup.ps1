   # TLS upgrade
        Clear-Host
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
        if(!(test-path $BaseFolder)){Write-host "." -NoNewline; new-item -itemtype Directory -Path $BaseFolder -ErrorAction SilentlyContinue | Out-Null }

    # Preparing Scripts
        $scripts = @(   "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_antibloat.ps1"
                        "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_security.ps1"
                        "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_settings.ps1")
            Foreach ($script in $scripts) {
                # Download Scripts
                    Write-host "." -NoNewline;
                    $filename = split-path $script -Leaf
                    $filedestination = join-path $BaseFolder -Childpath $filename
                    (New-Object net.webclient).Downloadfile("$script", "$filedestination")
                # Creating Missing Regpath
                    $reg_install = "HKLM:\Software\WinOptimizer"
                    If(!(Test-Path $reg_install)) {New-Item -Path $reg_install -Force | Out-Null;}
                # Creating Missing Regkeys
                    if (!((Get-Item -Path $reg_install).Property -match $filename)){Set-ItemProperty -Path $reg_install -Name $filename -Type String -Value 0}}

    # Preparing Functions
        $Link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/functions/WinOptimizer.psm1" 
        $Path = join-path -Path $Basefolder -ChildPath (split-path $link -Leaf)
        Invoke-WebRequest -Uri $Link -OutFile $Path -UseBasicParsing
        Import-Module $path
    