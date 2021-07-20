$date = (get-date -f "yyyy/MM/dd - HH:mm:ss")
$check_updates = choco outdated
$log = "$env:ProgramData\chocolatey\update_log.txt"

## Version 1.0

if ($check_updates -match "Chocolatey has determined 0 package") 
{
echo "`n$date - No update(s) found :)`n" $check_updates >> $log
echo "`n###################################################################################################" >> $log
}

else
{
echo "`n date - UPDATE(S) FOUND!! :O`n$" $check_updates >> $log
Checkpoint-Computer -Description "winoptimizer - appupdater" -RestorePointType "APPLICATION_INSTALL" | Out-Null #out-null waits for complete
choco upgrade all -y >> $log
echo "`n###################################################################################################" >> $log
}



