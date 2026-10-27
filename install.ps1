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

function Assert-NotepadBlocked {
    $notepad = Join-Path $env:WINDIR 'System32\notepad.exe'
    if (-not (Test-Path $notepad)) {
        Write-Warning "Notepad was not found at $notepad; the launch test was not performed."
        return
    }

    $process = $null
    try {
        $process = Start-Process $notepad -PassThru -ErrorAction Stop
    }
    catch {
        $exception = $_.Exception
        while ($exception.InnerException) {
            $exception = $exception.InnerException
        }

        if ($exception -is [System.ComponentModel.Win32Exception] -and $exception.NativeErrorCode -eq 5) {
            Write-Host 'Verified: the driver blocked notepad.exe with access denied.'
            return
        }

        throw
    }

    if ($process) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
        throw 'The driver is running, but notepad.exe was allowed to start.'
    }
}

if (Get-CimInstance Win32_SystemDriver -Filter "Name='wdacmini'" -ErrorAction SilentlyContinue) {
    throw 'The wdacmini service already exists. Run remove.ps1 before reinstalling.'
}

$bootConfiguration = & bcdedit.exe /enum '{current}' | Out-String
if ($LASTEXITCODE -ne 0) {
    throw 'Could not read the Windows boot configuration.'
}
if ($bootConfiguration -notmatch 'testsigning\s+Yes') {
    throw 'Windows test-signing mode is off. On a dedicated test machine with Secure Boot disabled, run bcdedit /set testsigning on from an elevated prompt and reboot before installing.'
}

$package = Join-Path $PSScriptRoot 'package'
$sys = Join-Path $package 'wdacmini.sys'
$inf = Join-Path $package 'wdacmini.inf'
$cat = Join-Path $package 'wdacmini.cat'
$cer = Join-Path $package 'wdacmini-test.cer'
foreach ($file in @($sys, $inf, $cat, $cer)) {
    if (-not (Test-Path $file)) {
        throw "Run prepare.ps1 first. Missing package file: $file"
    }
}

$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $cer
Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null

foreach ($file in @($sys, $cat)) {
    $signature = Get-AuthenticodeSignature $file
    if ($signature.Status -ne 'Valid') {
        throw "The test signature on $file is not valid after importing the certificate: $($signature.Status)"
    }
}

Invoke-Native 'rundll32.exe' @('setupapi.dll,InstallHinfSection', 'DefaultInstall', '132', $inf)
if (-not (Get-CimInstance Win32_SystemDriver -Filter "Name='wdacmini'" -ErrorAction SilentlyContinue)) {
    throw 'The INF command returned, but the wdacmini service was not created.'
}

Invoke-Native 'sc.exe' @('start', 'wdacmini')
Assert-NotepadBlocked
Write-Host 'WDAC Mini is installed and running. notepad.exe is blocked.'
Write-Host "Certificate thumbprint: $($certificate.Thumbprint)"
