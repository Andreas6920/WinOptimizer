        # Finding hosts file
        $hostsfile = "$env:SystemRoot\System32\drivers\etc\hosts"
        Write-Host "`t`- Hosts file found: $hostfile" -f Yellow
        
        # Taking backup of current hosts file first
        $backupfile = "$env:SystemRoot\System32\drivers\etc\hosts_backup"
        Write-Host "`t`t`t- Taking Backup of original hosts file ($backupfile)" -f Yellow
        Copy-Item $hostsfile $backupfile
        
        # Crawling new Microsoft tracking domains
        $domain = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/hosts.txt'  -UseBasicParsing
        $domain = $domain.Content | Foreach-object { $_ -replace "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "" } | Foreach-object { $_ -replace " ", "" }
        $domain = $domain.Split("`n") -notlike "#*" -notmatch "spynet2.microsoft.com" -match "\w"
        Write-Host "`t`t`t- Getting updated lists of Microsoft's trackers" -f Yellow
        
        # Adding crawled domains to hosts file
        Write-Host "`t`t`t- Blocking domains in your hosts file.." -f Yellow
        foreach ($domain_entry in $domain) {
        $counter++
                Write-Progress -Activity 'Adding entries to host file..' -CurrentOperation $domain_entry -PercentComplete (($counter /$domain.count) * 100)
                Add-Content -Encoding UTF8  $hostsfile ("`t" + "0.0.0.0" + "`t`t" + "$domain_entry") -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 200
        }
        #flush DNS cache
        ipconfig /flushdns | Out-Null; start-Sleep 2; nbtstat -R | Out-Null; 
        Write-Host "`t`t`t- hosts entries complete." -f Yellow
        
        Start-Sleep -s 5;

        Add-Type -AssemblyName System.Windows.Forms
        $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
        $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balmsg.BalloonTipText = 'Trackers are sucessfully blocked' 
        $balmsg.BalloonTipTitle = "Winoptimizer"
        $balmsg.Visible = $true
        $balmsg.ShowBalloonTip(20000)