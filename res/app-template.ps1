
######################################################################

$name = "REPLACE-ME-NAME" 
$app = "REPLACE-ME-APP"

# Windows notification
    Add-Type -AssemblyName System.Windows.Forms
    $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balmsg.BalloonTipText = 'Installing ' + $Name 
    $balmsg.BalloonTipTitle = "Winoptimizer"
    $balmsg.Visible = $true
    $balmsg.ShowBalloonTip(20000)

# Install
    choco install $app -y

######################################################################