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

function Start-Input {
    if (-not ('WinOptimizer.UserInput' -as [type])) {
        Add-Type -Namespace WinOptimizer -Name UserInput -MemberDefinition '[DllImport("user32.dll")] public static extern bool BlockInput(bool fBlockIt);'
    }

    [WinOptimizer.UserInput]::BlockInput($false) | Out-Null
}

function Stop-Input {
    if (-not ('WinOptimizer.UserInput' -as [type])) {
        Add-Type -Namespace WinOptimizer -Name UserInput -MemberDefinition '[DllImport("user32.dll")] public static extern bool BlockInput(bool fBlockIt);'
    }

    [WinOptimizer.UserInput]::BlockInput($true) | Out-Null
}

function Get-WinOptimizerMenuSelection {
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string[]]$Items
    )

    $SelectedIndex = 0
    while ($true) {
        Clear-Host
        Write-Host 'WinOptimizer' -ForegroundColor Yellow
        Write-Host $Title -ForegroundColor Cyan
        Write-Host ''

        for ($Index = 0; $Index -lt $Items.Count; $Index++) {
            if ([string]::IsNullOrWhiteSpace($Items[$Index])) {
                Write-Host ''
                continue
            }

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
            38 {$SelectedIndex = Get-WinOptimizerNextMenuSelection -Items $Items -SelectedIndex $SelectedIndex -Direction Previous}
            40 {$SelectedIndex = Get-WinOptimizerNextMenuSelection -Items $Items -SelectedIndex $SelectedIndex -Direction Next}
            13 {return $SelectedIndex}
            27 {return -1}
        }
    }
}

function Get-WinOptimizerNextMenuSelection {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string[]]$Items,
        [Parameter(Mandatory)]
        [int]$SelectedIndex,
        [Parameter(Mandatory)]
        [ValidateSet('Next', 'Previous')]
        [string]$Direction
    )

    $Step = if ($Direction -eq 'Next') {1} else {-1}
    do {$SelectedIndex = ($SelectedIndex + $Step + $Items.Count) % $Items.Count} while ([string]::IsNullOrWhiteSpace($Items[$SelectedIndex]))
    return $SelectedIndex
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

function Start-WinOptimizerAntiBloatMenu {
    $Items = @(
        '  Run ALL Settings:',
        '    Remove ALL Bloat:',
        '      Remove bloated apps and features',
        '      Remove bloated Startup Services',
        '      Remove bloated Scheduled Task',
        '      Remove bloated Printers',
        '    Clean ALL Windows:',
        '      Taskbar: Unpin Apps & Hide Features',
        '      Startmenu: Unpin Apps',
        '      LockScreen: Hide information',
        '      Desktop: Remove shortcuts, put files in a folder',
        '',
        '  Return'
    )

    while ($true) {
        $Selection = Get-WinOptimizerMenuSelection -Title 'Anti Bloat' -Items $Items
        if ($Selection -lt 0 -or $Selection -eq 12) {return}

        switch ($Selection) {
            0 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -All -CleanDesktop}}
            1 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -AllBloatware}}
            2 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanBloatApps}}
            3 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanServices}}
            4 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanScheduledTasks}}
            5 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanPrinters}}
            6 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -AllPinnedItems -CleanDesktop}}
            7 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanTaskbar}}
            8 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanStartMenu}}
            9 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanLockScreen}}
            10 {Invoke-WinOptimizerMenuAction {Start-WinAntiBloat -CleanDesktop}}
        }
    }
}

function Start-WinOptimizerSettingsMenu {
    $Items = @(
        '  Run ALL Settings:',
        '    Run ALL Privacy & Security Settings',
        '    Run ALL Explorer settings:',
        '      ShowFileExtension',
        '      ShowHiddenFiles',
        '      ChangeExplorerToThisPC',
        '    Fix Clock',
        '    Disable Auto Setup of network devices',
        '    Disable share of printers',
        '    Set Powerplan',
        '    Enable DarkMode',
        '    Set Wallpaper: WindowsSpotlight',
        '    Set Wallpaper: Default Wallpaper',
        '',
        '  Return'
    )

    while ($true) {
        $Selection = Get-WinOptimizerMenuSelection -Title 'Windows Setting' -Items $Items
        if ($Selection -lt 0 -or $Selection -eq 14) {return}

        switch ($Selection) {
            0 {
                Invoke-WinOptimizerMenuAction {
                    Start-WinSecurity
                    Start-WinSettings -All
                }
            }
            1 {Invoke-WinOptimizerMenuAction {Start-WinSecurity}}
            2 {Invoke-WinOptimizerMenuAction {Start-WinSettings -AllExplorerSettings}}
            3 {Invoke-WinOptimizerMenuAction {Start-WinSettings -ShowFileExtension}}
            4 {Invoke-WinOptimizerMenuAction {Start-WinSettings -ShowHiddenFiles}}
            5 {Invoke-WinOptimizerMenuAction {Start-WinSettings -ChangeExplorerToThisPC}}
            6 {Invoke-WinOptimizerMenuAction {Start-WinSettings -FixClock}}
            7 {Invoke-WinOptimizerMenuAction {Start-WinSettings -DisableAutoSetupNetworkDevices}}
            8 {Invoke-WinOptimizerMenuAction {Start-WinSettings -DisablePrinterSharing}}
            9 {Invoke-WinOptimizerMenuAction {Start-WinSettings -SetPowerPlan}}
            10 {Invoke-WinOptimizerMenuAction {Start-WinSettings -EnableDarkMode}}
            11 {Invoke-WinOptimizerMenuAction {Start-WinSettings -SetWallpaperWindowsSpotlight}}
            12 {Invoke-WinOptimizerMenuAction {Start-WinSettings -SetWallpaperDisableWindowsSpotlight}}
        }
    }
}

function Start-WinOptimizerSecurityMenu {
    $Items = @(
        '  Run ALL Settings:',
        '    Run ALL Privacy & Security Settings',
        '      Set ALL Privacy Settings',
        '      Set ALL Security Settings',
        '    Send Data Removal Request to Microsoft',
        '    Block ALL Domains:',
        '      Block Domains via Host File entries',
        '      Block Domains Via Firewall entries',
        '',
        '  Return'
    )

    while ($true) {
        $Selection = Get-WinOptimizerMenuSelection -Title 'Security Setting' -Items $Items
        if ($Selection -lt 0 -or $Selection -eq 9) {return}

        switch ($Selection) {
            0 {Invoke-WinOptimizerMenuAction {Start-WinSecurity}}
            1 {Invoke-WinOptimizerMenuAction {Start-WinSecurity}}
            2 {Invoke-WinOptimizerMenuAction {Start-WinSecurity -SetPrivacySettings}}
            3 {Invoke-WinOptimizerMenuAction {Start-WinSecurity -SetSecuritySettings}}
            4 {Invoke-WinOptimizerMenuAction {Start-WinSecurity -SendRemovalRequest}}
            5 {
                Invoke-WinOptimizerMenuAction {
                    Start-WinSecurity -BlockDomainHostFile -BlockDomainFirewall
                }
            }
            6 {Invoke-WinOptimizerMenuAction {Start-WinSecurity -BlockDomainHostFile}}
            7 {Invoke-WinOptimizerMenuAction {Start-WinSecurity -BlockDomainFirewall}}
        }
    }
}

function Start-WinOptimizer {
    $Items = @(
        'Run all',
        'AntiBloat',
        'Security',
        'Windows Settings',
        'Install',
        '',
        'Exit'
    )

    while ($true) {
        $Selection = Get-WinOptimizerMenuSelection -Title 'Main Menu' -Items $Items
        if ($Selection -lt 0 -or $Selection -eq 6) {return}

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
            2 {Start-WinOptimizerSecurityMenu}
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
