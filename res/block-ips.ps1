$blockip = Invoke-WebRequest -Uri https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt  -UseBasicParsing
$blockip = $blockip.Content | Foreach-object { $_ -replace "0.0.0.0 ", "" } | Out-String
$blockip = $blockip.Split("`n") -notlike "#*" -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
foreach ($ip_entry in $blockip) {
    netsh advfirewall firewall add rule name="Block Microsoft Tracking IP: $ip_entry" dir=out action=block remoteip=$ip_entry enable=yes | Out-Null}

    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = 'Firewall configured succesfully' 
    $balmsg.BalloonTipTitle = "Winoptimizer"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)