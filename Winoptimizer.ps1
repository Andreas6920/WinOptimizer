#Install
    $admin_permissions_check = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $admin_permissions_check = $admin_permissions_check.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin_permissions_check) {

    $Link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/functions/setup.ps1" 
    $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath (split-path $link -Leaf)
    Invoke-WebRequest -Uri $Link -OutFile $Path -UseBasicParsing
    Import-Module $path
    







    }
    else {
        1..99 | % {
            $Warning_message = "POWERSHELL IS NOT RUNNING AS ADMINISTRATOR. Please close this and run this script as administrator."
            cls; ""; ""; ""; ""; ""; Write-Host $Warning_message -ForegroundColor White -BackgroundColor Red; ""; ""; ""; ""; ""; Start-Sleep 1; cls
            cls; ""; ""; ""; ""; ""; Write-Host $Warning_message -ForegroundColor White; ""; ""; ""; ""; ""; Start-Sleep 1; cls
        }    
    } 
