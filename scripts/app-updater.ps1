

#  Wait for inactivity    
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
Do  {$mouseactivity1 = [System.Windows.Forms.Cursor]::Position
    Start-Sleep -s 180
    $mouseactivity2 = [System.Windows.Forms.Cursor]::Position} 
While ($mouseactivity2 -ne $mouseactivity1)


# Initiate script
$logfile = Join-path -Path $env:ProgramData -ChildPath "\chocolatey\app-updater_log.txt"
$string = "`n`t- DATE:" + (Get-Date -Format " yyyy/MM/dd HH:mm:sss")
Add-Content -Value $string -Path $logfile -Encoding UTF8

Write-host "- Checking Network Connection:" -nonewline
if (Test-Connection www.github.com -Quiet){

	# Setup network connection
	Write-host " VERIFIED" -f Green
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
	Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1

	$string = "`t- NETWORK CONNECTION: VERIFIED"
	Add-Content -Value $string -Path $logfile -Encoding UTF8

# Scriptupdater
    $version = "Version 3.5"
    $link = (Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1").Content
    $scriptlocation = Join-Path -path $env:programdata -ChildPath "\Chocolatey\app-updater.ps1"
	if (!($link -cMatch $version )){write-host "updating..."; start-sleep -s 3; set-content -Value $link -Path $scriptlocation -Force; set-location ($scriptlocation| Split-Path -Parent)}

# App-updater Variables
	$code = choco outdated -r 
	$logfile = Join-path -Path $env:ProgramData -ChildPath "\chocolatey\app-updater_log.txt"	

# if outdated application is detected
	if ($code -ne $null){
		#$date2 = Get-Date -Format "[yyyy/MM/dd HH:MM:ss]"
		$string = "`t- UPDATES DETECTED:"
		Write-host "- Updating:"
		Add-Content -Value $string -Path $logfile -Encoding UTF8
		foreach ($app in $code){
			
			# Define values from choco output
				$software = ($app.Split("|")[0]).toupper()
				$currentversion = $app.Split("|")[1]
				$newestversion = $app.Split("|")[2]			
			
			# Update
				Add-Content -Value "`t`t- $software" -Path $logfile -Encoding UTF8
				write-host "`t- $software..." -nonewline
				$string = "`t`t`t- UPDATING:`tVersion: $currentversion -> $newestversion"
				Add-Content -Value $string -Path $logfile -Encoding UTF8
				$update = choco upgrade $software -y
			
			# Logging: Sucessfull update
				if($update -match "The upgrade of.*was successful."){
					$msg = (($update | Select-String -Pattern " The upgrade of.*was successful.").Matches.Value).trim()
					if($msg -match ". The upgrade"){$msg = $msg.replace(".","#").Split('#').Trim()[2]}
					write-host "COMPLETED" -f Green
					$string = "`t`t`t- SUCCESS:`t$msg"
					Add-Content -Value $string -Path $logfile -Encoding UTF8}
					
			# Logging: Unsuccessful update
				elseif($update -match "The upgrade of.*was NOT successful."){
					$msg = (($update | Select-String -Pattern "The upgrade of.*was NOT successful.").Matches.Value).trim()
					$string = "`t`t`t- ERROR:`t$msg"
					Add-Content -Value $string -Path $logfile -Encoding UTF8
					write-host "FAILED" -f Red
					$msg = $update | Select-String -Pattern "^ERROR:"
					$msg = ($msg -split "Exit code indicates the following: ")[1]
					if ($msg -ne $null){
					$string = "`t`t`t- INFO:`t`t$msg"
					Add-Content -Value $string -Path $logfile -Encoding UTF8}
					}}	
		
		$string = "`t- SYSTEM UPDATED (" + (Get-Date -Format "yyyy/MM/dd HH:mm:sss") + ")"
        Add-Content -Value $string -Path $logfile -Encoding UTF8
	}

# if no updates is detected
	else{   $string = "`t- NO UPDATES DETECTED."
	        Add-Content -Value $string -Path $logfile -Encoding UTF8}}

else{$string = "`t- No Network Connection. Trying again tomrrow."; Add-Content -Value $string -Path $logfile -Encoding UTF8 }

# Ending script
	$separator = "#" * 99
	$string = "`n$separator"
	Add-Content -Value $string -Path $logfile -Encoding UTF8 