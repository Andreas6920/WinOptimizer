$version = "Version 2.5"
$link = (Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1").Content
$scriptlocation = Join-Path -path $env:programdata -ChildPath "\Chocolatey\app-updater.ps1"
$date = (get-date -f "yyyy/MM/dd - HH:mm:ss")
$check_updates = choco outdated
$log = "$env:ProgramData\chocolatey\app-updater_log.txt"

# Get latest version of script
    if(Test-Connection www.github.com -Quiet){
    if (!($link -cMatch $version )){write-host "updating..."; start-sleep -s 3; set-content -Value $link -Path $scriptlocation -Force; set-location ($scriptlocation| Split-Path -Parent)}}

# Updater script

    # if no updates available, just write to logs that scan is done and nothing found.
    if ($check_updates -match "Chocolatey has determined 0 package") 
    {   echo "`n$date - No update(s) found :)`n" $check_updates >> $log
        echo "`n###################################################################################################" >> $log}

    # if updates found, update and add to logs
    else
    {   echo "`n$date - UPDATE(S) FOUND!! :O`n$" $check_updates >> $log
        Checkpoint-Computer -Description "winoptimizer - appupdater" -RestorePointType "APPLICATION_INSTALL" | Out-Null #out-null waits for complete
        choco upgrade all -y >> $log
        echo "`n###################################################################################################" >> $log}