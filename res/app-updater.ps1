# auto-updater
if(Test-Connection www.github.com -Quiet){
    $this_version = "Version 2.0"
    $version = (Invoke-WebRequest "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/app-updater/app-updater.ps1").Content
    if ($version -cmatch "$this_version")
    {write "same"}
    else {
    remove-item "$env:ProgramData\chocolatey\app-updater.ps1" -Force; sleep -s 5
    Invoke-WebRequest "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/app-updater/app-updater.ps1" -OutFile "$env:ProgramData\chocolatey\app-updater.ps1" -UseBasicParsing | out-null
    sleep -s 5
    powershell -ep bypass -runas Verb "$env:ProgramData\chocolatey\app-updater.ps1"
     }
    }

$date = (get-date -f "yyyy/MM/dd - HH:mm:ss")
$check_updates = choco outdated
$log = "$env:ProgramData\chocolatey\update_log.txt"

# if no updates available, just write to logs that scan is done and nothing found.
if ($check_updates -match "Chocolatey has determined 0 package") 
{
echo "`n$date - No update(s) found :)`n" $check_updates >> $log
echo "`n###################################################################################################" >> $log
}

# if updates found, update and add to logs
else
{
echo "`n$date - UPDATE(S) FOUND!! :O`n$" $check_updates >> $log
Checkpoint-Computer -Description "winoptimizer - appupdater" -RestorePointType "APPLICATION_INSTALL" | Out-Null #out-null waits for complete
choco upgrade all -y >> $log
echo "`n###################################################################################################" >> $log
}


