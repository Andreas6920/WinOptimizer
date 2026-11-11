function Get-LogDate {
    Get-Date -Format '[yyyy/MM/dd HH:mm:ss]'
}

function Test-WinOptimizerAdministrator {
    $WindowsPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-WinOptimizerAdministrator {
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )

    if (-not (Test-WinOptimizerAdministrator)) {
        Write-Warning "$Action requires an elevated PowerShell session. Close this window, reopen PowerShell as Administrator, reload WinOptimizer, and try again. No changes were made."
        return $false
    }

    return $true
}

function Add-Reg {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword', 'Unknown')]
        [string]$Type,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    try {
        if (-not (Test-Path $Path)) {New-Item -Path $Path -Force | Out-Null}

        $CurrentValue = $null
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {$CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue}

        if ($CurrentValue -ne $Value) {
            New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
            Write-Host "$(Get-LogDate)`t            - Setting '$Name' to '$Value'." -ForegroundColor DarkYellow
        } else {
            Write-Host "$(Get-LogDate)`t            - '$Name' is already '$Value'." -ForegroundColor DarkYellow
        }
    } catch {
        if ($_.Exception.GetType().Name -eq 'UnauthorizedAccessException') {
            Write-Host "$(Get-LogDate)`t            - Access denied to modify '$Name'." -ForegroundColor Red
        } else {
            Write-Host "`t            - ERROR - cannot modify '$Name': $_" -ForegroundColor Red
        }
    }
}

function Restart-Explorer {
    if (Get-Process -Name 'Explorer' -ErrorAction SilentlyContinue) {
        Stop-Process -Name 'Explorer' -Force -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 2
        if (-not (Get-Process -Name Explorer -ErrorAction SilentlyContinue)) {Start-Process Explorer -ErrorAction SilentlyContinue}
    }

    $WindowName = $Host.UI.RawUI.WindowTitle
    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.Interaction]::AppActivate($WindowName)
}

function Get-WinOptimizerMenuSelection {
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [Parameter(Mandatory)]
        [string[]]$Items
    )

    $SelectedIndex = 0
    while ($true) {
        Clear-Host
        Write-Host 'WinOptimizer' -ForegroundColor Yellow
        Write-Host $Title -ForegroundColor Cyan
        Write-Host ''

        for ($Index = 0; $Index -lt $Items.Count; $Index++) {
            if ($Index -eq $SelectedIndex) {
                Write-Host "  > $($Items[$Index])" -ForegroundColor Black -BackgroundColor Yellow
            } else {
                Write-Host "    $($Items[$Index])"
            }
        }

        Write-Host ''
        Write-Host 'Use the Up/Down arrow keys and Enter. Press Esc to go back or exit.'
        $Key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        switch ($Key.VirtualKeyCode) {
            38 {$SelectedIndex = ($SelectedIndex - 1 + $Items.Count) % $Items.Count}
            40 {$SelectedIndex = ($SelectedIndex + 1) % $Items.Count}
            13 {return $SelectedIndex}
            27 {return -1}
        }
    }
}

function Invoke-WinOptimizerMenuAction {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    try {
        & $Action
    } catch {
        Write-Error "WinOptimizer action failed: $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Host 'Press any key to return to the menu.'
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Confirm-WinOptimizerDesktopCleanup {
    Write-Warning 'Clean Desktop moves the current user desktop contents and permanently removes all Public Desktop contents.'
    $Confirmation = Read-Host "Type YES to continue"
    return $Confirmation -ceq 'YES'
}

function Start-WinOptimizerAntiBloatMenu {
    $Items = @(
        'Run all standard AntiBloat sections',
        'Run all bloatware sections',
        'Run all pinned-item sections',
        'Clean Desktop (moves user files and removes Public Desktop contents)',
        'Clean Taskbar',
        'Clean Lock Screen',
        'Clean Start Menu',
        'Remove bloat apps',
        'Disable selected services',
        'Disable selected scheduled tasks',
        'Clean printers'
    )

    while ($true) {
        $Selection = Get-WinOptimizerMenuSelection -Title 'AntiBloat' -Items $Items
        if ($Selection -lt 0) {return}

        switch ($Selection) {
            0 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -All}}
            1 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -AllBloatware}}
            2 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -AllPinnedItems}}
            3 {
                if (Confirm-WinOptimizerDesktopCleanup) {
                    Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanDesktop}
                }
            }
            4 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanTaskbar}}
            5 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanLockScreen}}
            6 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanStartMenu}}
            7 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanBloatApps}}
            8 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanServices}}
            9 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanScheduledTasks}}
            10 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanPrinters}}
        }
    }
}

function Start-WinOptimizerSettingsMenu {
    $Items = @(
        'Run all settings',
        'Run all Explorer settings',
        'Show file extensions',
        'Show hidden files',
        'Open Explorer to This PC',
        'Fix clock (24-hour, seconds, and dd/MM/yyyy date)',
        'Enable Dark Mode',
        'Enable Windows Spotlight wallpaper',
        'Disable Windows Spotlight wallpaper'
    )

    while ($true) {
        $Selection = Get-WinOptimizerMenuSelection -Title 'Windows Settings' -Items $Items
        if ($Selection -lt 0) {return}

        switch ($Selection) {
            0 {Invoke-WinOptimizerMenuAction {Start-WinSettings -All}}
            1 {Invoke-WinOptimizerMenuAction {Start-WinSettings -AllExplorerSettings}}
            2 {Invoke-WinOptimizerMenuAction {Start-WinSettings -ShowFileExtension}}
            3 {Invoke-WinOptimizerMenuAction {Start-WinSettings -ShowHiddenFiles}}
            4 {Invoke-WinOptimizerMenuAction {Start-WinSettings -ChangeExplorerToThisPC}}
            5 {Invoke-WinOptimizerMenuAction {Start-WinSettings -FixClock}}
            6 {Invoke-WinOptimizerMenuAction {Start-WinSettings -EnableDarkMode}}
            7 {Invoke-WinOptimizerMenuAction {Start-WinSettings -SetWallpaperWindowsSpotlight}}
            8 {Invoke-WinOptimizerMenuAction {Start-WinSettings -SetWallpaperDisableWindowsSpotlight}}
        }
    }
}

function Start-WinOptimizer {
    $Items = @(
        'Run all standard sections',
        'AntiBloat',
        'Security',
        'Windows Settings',
        'Install Apps',
        'Exit'
    )

    while ($true) {
        $Selection = Get-WinOptimizerMenuSelection -Title 'Main Menu' -Items $Items
        if ($Selection -lt 0 -or $Selection -eq 5) {return}

        switch ($Selection) {
            0 {
                if (-not (Test-WinOptimizerAdministrator)) {
                    Write-Warning 'Running all sections requires an elevated PowerShell session. No changes were made. Reopen PowerShell as Administrator and start WinOptimizer again.'
                    Start-Sleep -Seconds 3
                } else {
                    Invoke-WinOptimizerMenuAction {
                        Start-WinAntiBloat -All
                        Start-WinSecurity
                        Start-WinSettings -All
                    }
                }
            }
            1 {Start-WinOptimizerAntiBloatMenu}
            2 {Invoke-WinOptimizerMenuAction {Start-WinSecurity}}
            3 {Start-WinOptimizerSettingsMenu}
            4 {Invoke-WinOptimizerMenuAction {Install-App}}
        }
    }
}

. (Join-Path $PSScriptRoot '..\scripts\Start-WinAntiBloat.ps1')
. (Join-Path $PSScriptRoot '..\scripts\Start-WinSecurity.ps1')
. (Join-Path $PSScriptRoot '..\scripts\Start-WinSettings.ps1')
. (Join-Path $PSScriptRoot '..\scripts\Install-App.ps1')

Export-ModuleMember -Function Start-WinOptimizer, Start-WinAntiBloat, Start-WinSecurity, Start-WinSettings, Install-App
