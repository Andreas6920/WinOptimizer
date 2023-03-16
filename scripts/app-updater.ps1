# Prepare varibles
    $version = "Version 2.9"
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
    $link = (Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1").Content
    $scriptlocation = Join-Path -path $env:programdata -ChildPath "\Chocolatey\app-updater.ps1"
    $check_updates = choco outdated
    $check_updates_negative = choco outdated | select-string "Chocolatey has determined"
    $check_updates_positive = choco outdated | select-string "false"
    $update = choco upgrade all -y | Select-string "has been installed."
    $loglocation = Join-path -Path $env:ProgramData -ChildPath "\chocolatey\app-updater_log.txt"

#  Wait for inactivity    
    do {$a = [System.Windows.Forms.Cursor]::Position
        Start-Sleep -s 240
        $b = [System.Windows.Forms.Cursor]::Position} 
    while ($b -ne $a)

# Get latest version of script
    if(Test-Connection www.github.com -Quiet){
    if (!($link -cMatch $version )){write-host "updating..."; start-sleep -s 3; set-content -Value $link -Path $scriptlocation -Force; set-location ($scriptlocation| Split-Path -Parent)}}

# if updates not found, add that to the logs.
    if ($check_updates -match "Chocolatey has determined 0 package"){
        $date = get-date -f "yyyy/MM/dd - HH:mm:ss"
        Add-Content -Value "`n$date - No update(s) found :)`n" -Path $loglocation -Encoding UTF8
        Add-Content -Value $check_updates_negative -Path $loglocation -Encoding UTF8
        Add-Content -Value "`n###################################################################################################" -Path $loglocation -Encoding UTF8}

# if updates found, update and add to logs
    else{
        $date = get-date -f "yyyy/MM/dd - HH:mm:ss"
        Add-Content -Value "`n$date - UPDATE(S) FOUND!! :O`n" -Path $loglocation -Encoding UTF8
        Add-Content -Value $check_updates_positive -Path $loglocation -Encoding UTF8
        Checkpoint-Computer -Description "Winoptimizer - appupdater" -RestorePointType "APPLICATION_INSTALL" | Out-Null
        Add-Content -Value $update -Path $loglocation -Encoding UTF8
        Add-Content -Value "`n###################################################################################################" -Path $loglocation -Encoding UTF8}
