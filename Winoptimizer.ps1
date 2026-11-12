$RepositoryRoot = 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main'
$InstallRoot = Join-Path $env:TEMP 'WinOptimizer'
# Keep the repository's relative layout so the module can load its scripts and banner.
$FilesToDownload = @(
    'functions/WinOptimizer.psm1',
    'scripts/Start-WinAntiBloat.ps1',
    'scripts/Start-WinSecurity.ps1',
    'scripts/Start-WinSettings.ps1',
    'scripts/Install-App.ps1',
    'assets/ascii-winoptimizer.txt'
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

foreach ($RelativePath in $FilesToDownload) {
    $DestinationPath = Join-Path $InstallRoot ($RelativePath -replace '/', '\')
    $DestinationDirectory = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path -LiteralPath $DestinationDirectory -PathType Container)) {New-Item -ItemType Directory -Path $DestinationDirectory -Force -ErrorAction Stop | Out-Null}

    $FileUrl = "$RepositoryRoot/$RelativePath"
    Invoke-WebRequest -Uri $FileUrl -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
}

$ModulePath = Join-Path $InstallRoot 'functions\WinOptimizer.psm1'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
Import-Module -Name $ModulePath -Global -Force -ErrorAction Stop
