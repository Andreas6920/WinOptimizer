cls

# Preparing
    #IE First run
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null}
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1

    $shell = New-Object -ComObject "Shell.Application"
    $shell.minimizeall()

    Add-Type -AssemblyName System.Windows.Forms
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipText = 'Downloader i baggrunden...                           Forventet tid: 10 minutter'
    $balloon.BalloonTipTitle = "Microsoft Office"
    $balloon.Visible = $true 
    $balloon.ShowBalloonTip(90000)

# Office 
    if(!(test-path HKLM:\Software\Microsoft\Office\)){
    Write-host "`tOffice installeres:" -f green; Sleep -s 2
    Write-host "`t`t- Kontrollere om office allerede er installeret.."; Sleep -s 1
    # Download and install office
    $file = "C:\Programdata\file.ps1"
    Invoke-WebRequest -uri "https://geany.org/p/AH0Uu/raw/" -OutFile $file
    Write-host "`t`t- Dette kan tage op til 10 minutter. nuværende tidspunkt:" (get-date -f "HH:mm:ss...") -f white
    # Run Script
    Start-Process cmd -Verb RunAs -WindowStyle Hidden -ArgumentList "/c","powershell -ep bypass $file" -Wait; Sleep -s 10;
    Write-host "`t`t- Office 2019 Installeret!" (get-date -f "HH:mm:ss...") -f green; Sleep -s 5
    Remove-Item $file -Force -ea Ignore}

# Activator
    Add-Type -AssemblyName System.Windows.Forms
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipText = 'Aktiveres...                           Forventet tid: 5 minutter'
    $balloon.BalloonTipTitle = "Microsoft Office"
    $balloon.Visible = $true 
    $balloon.ShowBalloonTip(90000)

    Write-host "`tOffice aktiveres:" -f green; Sleep -s 2
    Write-host "`t`t- klargører system..."; Sleep -s 1
    
    #7zip installation
    if(!(Test-Path "$($env:ProgramFiles)\7-Zip\7z.exe")){
    $dlurl = 'https://7-zip.org/' + (Invoke-WebRequest -Uri 'https://7-zip.org/' | Select-Object -ExpandProperty Links | Where-Object {($_.innerHTML -eq 'Download') -and ($_.href -like "a/*") -and ($_.href -like "*-x64.exe")} | Select-Object -First 1 | Select-Object -ExpandProperty href)
    $installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
    Invoke-WebRequest $dlurl -OutFile $installerPath -UseBasicParsing
    Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait}
    
    #Activation
    $link = "https://github.com/abbodi1406/KMS_VL_ALL_AIO/releases/download/v0.40.0/KMS_VL_ALL_AIO-40.7z"
    $folder = "$($env:TEMP)\KMS_VL_ALL_AIO-40"
    $file = (Join-Path $folder (Split-Path $link -Leaf))
    Write-host "`t`t- Opretter mapper..."; Sleep -s 1
    mkdir $folder -ea Ignore | Out-Null
    Write-host "`t`t- Downloading file..."; Sleep -s 1
    Invoke-WebRequest -uri $link -OutFile $file
    & "C:\Program Files\7-Zip\7z.exe" x -o"$folder" -y -p"2020" "$file" | Out-Null
    Remove-Item $file -Force -ea Ignore
    $file = (Get-ChildItem -Path $folder | where {$_.extension -in ".cmd"}).FullName
    ((Get-Content -path $file -Raw) -replace 'set uAutoRenewal=0', "set uAutoRenewal=1" ) | Set-Content -Path $file
    Write-host "`t`t- Aktiveringen kører i baggrunden..."; Sleep -s 2
    Write-host "`t`t- Dette kan tage op til 5 minutter. nuværende tidspunkt:" (get-date -f "HH:mm:ss...") -f white
    Start-Process cmd -WindowStyle Hidden -Verb RunAs -ArgumentList "/c","$file" -Wait
    Write-host "`t`t- Office 2019 er aktiveret!" (get-date -f "HH:mm:ss...") -f green;
    Remove-Item $file -Force -ea Ignore

    Add-Type -AssemblyName System.Windows.Forms
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon
    $path = (Get-Process -id $pid).Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipText = 'Er nu installeret og aktiveret.'
    $balloon.BalloonTipTitle = "Microsoft Office"
    $balloon.Visible = $true 
    $balloon.ShowBalloonTip(90000)