param([switch]$Publish, [string]$OutputDirectory = 'dist/win-x64')
$ErrorActionPreference = 'Stop'
$connectRoot = Split-Path -Parent $PSScriptRoot
$dotnetPath = Join-Path $connectRoot '.tools\dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnetPath)) { $dotnetPath = (Get-Command dotnet -ErrorAction Stop).Source }
$env:DOTNET_CLI_HOME = Join-Path $connectRoot '.cache\dotnet-home'
$env:NUGET_PACKAGES = Join-Path $connectRoot '.cache\nuget'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_NOLOGO = '1'
Push-Location -LiteralPath $connectRoot
try {
    & (Join-Path $PSScriptRoot 'build-assets.ps1')
    & $dotnetPath build src/EclipseConnect.App/EclipseConnect.App.csproj -c Release --nologo -m:1
    if ($LASTEXITCODE -ne 0) { throw 'Application build failed' }
    & $dotnetPath run --project tests/EclipseConnect.Tests/EclipseConnect.Tests.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Regression tests failed' }
    if ($Publish) {
        $connectOutput = [IO.Path]::GetFullPath((Join-Path $connectRoot $OutputDirectory))
        $connectDistRoot = [IO.Path]::GetFullPath((Join-Path $connectRoot 'dist')) + [IO.Path]::DirectorySeparatorChar
        if (-not $connectOutput.StartsWith($connectDistRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Publish output must be a subdirectory of project dist' }
        & $dotnetPath publish src/EclipseConnect.App/EclipseConnect.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $connectOutput --nologo -m:1
        if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
    }
} finally { Pop-Location }
