    # Crawling updated list of Microsoft's Tracking IP's
    Write-Host "`t`t`t- Getting updated lists of Microsoft's trackin IP's" -f Yellow
    $blockip = Invoke-WebRequest -Uri https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt  -UseBasicParsing
    $blockip = $blockip.Content | Foreach-object { $_ -replace "0.0.0.0 ", "" } | Out-String
    $blockip = $blockip.Split("`n") -notlike "#*" -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

    # Adding IP's to firewall configuration
    Write-Host "`t`t`t- Configuring blocking rules in your firewall.." -f Yellow
    foreach ($ip_entry in $blockip) {
        $counter++
        Write-Progress -Activity 'Configuring firewall rules..' -CurrentOperation $ip_entry -PercentComplete (($counter /$blockip.count) * 100)
        netsh advfirewall firewall add rule name="Block Microsoft Tracking IP: $ip_entry" dir=out action=block remoteip=$ip_entry enable=yes | Out-Null}
    Write-Progress -Completed -Activity "make progress bar dissapear"
    Write-Host "`t`t`t- Firewall configuration complete." -f Yellow
    
    Start-Sleep -s 5;

    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = 'Firewall configured succesfully' 
    $balmsg.BalloonTipTitle = "Winoptimizer"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)