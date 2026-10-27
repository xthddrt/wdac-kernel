param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-MSBuild {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $path = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
        if ($path) {
            return $path
        }
    }

    $command = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw 'Visual Studio MSBuild was not found.'
}

function Find-SignTool {
    $bin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $path = Get-ChildItem $bin -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1

    if (-not $path) {
        throw 'The Windows SDK signtool.exe was not found.'
    }

    return $path
}

$solution = Join-Path $PSScriptRoot 'wdac-kernel.sln'
$package = Join-Path $PSScriptRoot "bin\x64\$Configuration\wdacmini"
$msbuild = Find-MSBuild
$arguments = @(
    $solution,
    '-m',
    "-p:Configuration=$Configuration",
    '-p:Platform=x64',
    '-v:minimal'
)

$sdkBuild = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\build'
$infVerif = Get-ChildItem $sdkBuild -Filter InfVerif.dll -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq 'x86' } |
    Select-Object -First 1
if (-not $infVerif) {
    Write-Warning 'The x86 InfVerif.dll required by this WDK is missing; package verification will be skipped. Inf2Cat will still run.'
    $arguments += '-p:SkipPackageVerification=true'
}

& $msbuild @arguments
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}

$sys = Join-Path $package 'wdacmini.sys'
$cat = Join-Path $package 'wdacmini.cat'
$cer = Join-Path $package 'wdacmini-test.cer'
foreach ($file in @($sys, $cat)) {
    if (-not (Test-Path $file)) {
        throw "Expected package file is missing: $file"
    }
}

$subject = 'CN=WDAC Mini Test Signing'
$certificate = Get-ChildItem 'Cert:\CurrentUser\My' |
    Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $certificate) {
    $certificateParameters = @{
        Type = 'CodeSigningCert'
        Subject = $subject
        CertStoreLocation = 'Cert:\CurrentUser\My'
        KeyAlgorithm = 'RSA'
        KeyLength = 2048
        KeyExportPolicy = 'NonExportable'
        HashAlgorithm = 'SHA256'
        NotAfter = (Get-Date).AddYears(1)
    }
    $certificate = New-SelfSignedCertificate @certificateParameters
}

Export-Certificate -Cert $certificate -FilePath $cer -Force | Out-Null
$signtool = Find-SignTool
foreach ($file in @($sys, $cat)) {
    $signArguments = @('sign', '/fd', 'SHA256', '/sha1', $certificate.Thumbprint, $file)
    & $signtool @signArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Signing failed for $file with exit code $LASTEXITCODE."
    }

    $signature = Get-AuthenticodeSignature $file
    if ($signature.Status -eq 'NotSigned' -or -not $signature.SignerCertificate) {
        throw "No signature was attached to $file."
    }
}

$readyPackage = Join-Path $PSScriptRoot 'package'
New-Item -ItemType Directory -Path $readyPackage -Force | Out-Null
$inf = Join-Path $package 'wdacmini.inf'
Copy-Item -Path @($sys, $cat, $cer, $inf) -Destination $readyPackage -Force

Write-Host "Prepared test-signed package: $readyPackage"
Write-Host 'The certificate is not trusted by this computer until install.ps1 imports it.'
