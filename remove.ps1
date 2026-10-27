#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    $output = & $FilePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "$FilePath failed with exit code ${exitCode}: $output"
    }
}

$service = Get-CimInstance Win32_SystemDriver -Filter "Name='wdacmini'" -ErrorAction SilentlyContinue
if ($service) {
    if ($service.State -eq 'Running') {
        Invoke-Native 'sc.exe' @('stop', 'wdacmini')
        Start-Sleep -Seconds 1
    }
    Invoke-Native 'sc.exe' @('delete', 'wdacmini')
}
else {
    Write-Host 'The wdacmini service is not installed.'
}

$package = Join-Path $PSScriptRoot 'package'
$sys = Join-Path $package 'wdacmini.sys'
$installedSys = Join-Path $env:WINDIR 'System32\drivers\wdacmini.sys'
if ((Test-Path $sys) -and (Test-Path $installedSys)) {
    if ((Get-FileHash $sys).Hash -eq (Get-FileHash $installedSys).Hash) {
        try {
            Remove-Item $installedSys -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "The installed driver file could not be removed yet: $installedSys"
        }
    }
    else {
        Write-Warning "The installed driver differs from this package and was left in place: $installedSys"
    }
}

$cer = Join-Path $package 'wdacmini-test.cer'
if (Test-Path $cer) {
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $cer
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $path = "Cert:\LocalMachine\$store\$($certificate.Thumbprint)"
        if (Test-Path $path) {
            Remove-Item $path -Force
        }
    }
}

Write-Host 'WDAC Mini removal is complete.'
