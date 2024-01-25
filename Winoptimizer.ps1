#Install
    $admin_permissions_check = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $admin_permissions_check = $admin_permissions_check.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin_permissions_check) {
    
        # TLS upgrade
            Clear-Host
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Write-host "Loading" -NoNewline

        # Install Shit
            $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
            if(!(test-path $BaseFolder)){Write-host "." -NoNewline; new-item -itemtype Directory -Path $BaseFolder -ErrorAction SilentlyContinue | Out-Null }

            $modulepath = $env:PSmodulepath.split(";")[1]
            $module = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/functions/WinOptimizer.psm1"
            $file = (split-path $module -Leaf)
            $filename = $file.Replace(".psm1","").Replace(".ps1","").Replace(".psd","")
            $filedestination = "$modulepath/$filename/$file"
            $filesubfolder = split-path $filedestination -Parent
            If (!(Test-Path $filesubfolder )) {New-Item -ItemType "Directory" -Path $filesubfolder -Force | Out-Null; Start-Sleep -S 1}
            # Download module
            (New-Object net.webclient).Downloadfile($module, $filedestination)
            # Install module
            Import-module -name $filename
    

        # Preparing Functions
        
        
    }
    else {
        1..99 | % {
            $Warning_message = "POWERSHELL IS NOT RUNNING AS ADMINISTRATOR. Please close this and run this script as administrator."
            cls; ""; ""; ""; ""; ""; Write-Host $Warning_message -ForegroundColor White -BackgroundColor Red; ""; ""; ""; ""; ""; Start-Sleep 1; cls
            cls; ""; ""; ""; ""; ""; Write-Host $Warning_message -ForegroundColor White; ""; ""; ""; ""; ""; Start-Sleep 1; cls
        }    
    } 
