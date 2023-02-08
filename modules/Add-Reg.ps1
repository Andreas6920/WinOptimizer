function Add-Reg {

    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword',' Unknown')]
        [String]$Type,
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

If (!(Test-Path $path)) {New-Item -Path $path -Force | Out-Null}; 
Set-ItemProperty -Path $path -Name $name -Type $type -Value $value -Force | Out-Null

}