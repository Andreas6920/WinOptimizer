$date = (get-date -f "yyyy/MM/dd - HH:mm:ss")
$check_updates = choco outdated
$log = "$env:ProgramData\chocolatey\update_log.txt"

if ($check_updates -match "Chocolatey has determined 0 package") 
{
echo "`n `n$date - No update found :)" $check_updates "`n-------------------------------------------------------------------------" >> $log
}

else
{
echo "`n `n$date - update found!!" $check_updates "`n-------------------------------------------------------------------------" >> $log
Checkpoint-Computer -Description "winoptimizer - appupdater" -RestorePointType "APPLICATION_INSTALL" | Out-Null #out-null waits for complete
choco upgrade all -y
}
