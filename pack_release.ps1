[CmdletBinding()]
param(
    [string]$Version = 'v1.0.0',
    [string]$OutputRoot = 'dist'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) {
    $ProjectRoot = (Get-Location).Path
}
$ProjectRoot = (Resolve-Path $ProjectRoot).Path

$ReleaseName = "OnAuth-Source-$Version"
$StagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) "$ReleaseName-staging-$(Get-Date -Format 'yyyyMMddHHmmss')"
$OutputDir = Join-Path $ProjectRoot $OutputRoot
$ZipPath = Join-Path $OutputDir "$ReleaseName.zip"

$TopLevelIncludes = @(
    '.gitignore',
    'README.md',
    'LICENSE',
    'requirements.txt',
    'requirements-dev.txt',
    'main.py',
    'app_factory.py',
    'bootstrap.py',
    'config.py',
    'database.py',
    'template_env.py',
    'alembic.ini',
    'pytest.ini',
    'Test_App_A.py',
    'admin_web',
    'alembic',
    'client_tools',
    'routers',
    'schemas',
    'user_web',
    'utils',
    'tenant_web',
    'middlewares'
)

$ExcludeNames = @(
    '.git',
    '.venv',
    'venv',
    'env',
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    '.idea',
    '.vscode',
    'build',
    'dist',
    'uploads',
    'node_modules',
    'Test.py'
)

$ExcludeFilePatterns = @(
    '*.pyc',
    '*.pyo',
    '*.pyd',
    '*.db',
    '*.sqlite',
    '*.sqlite3',
    '.env',
    '.env.*',
    '*.local',
    '*.crt',
    '*.key',
    '*.log',
    '*.zip',
    'pack_release.ps1',
    'pack_release.bat'
)

function Remove-ReleaseNoise {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    Get-ChildItem -LiteralPath $Root -Force -Recurse -Directory |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object {
            if ($ExcludeNames -contains $_.Name) {
                Remove-Item -LiteralPath $_.FullName -Recurse -Force
            }
        }

    Get-ChildItem -LiteralPath $Root -Force -Recurse -File |
        ForEach-Object {
            $shouldRemove = $false

            if ($ExcludeFilePatterns -contains $_.Name) {
                $shouldRemove = $true
            }
            else {
                foreach ($pattern in $ExcludeFilePatterns) {
                    if ($_.Name -like $pattern) {
                        $shouldRemove = $true
                        break
                    }
                }
            }

            if ($shouldRemove) {
                Remove-Item -LiteralPath $_.FullName -Force
            }
        }
}

function Copy-ReleaseItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot
    )

    $SourcePath = Join-Path $ProjectRoot $Name
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        Write-Warning "Skip missing item: $Name"
        return
    }

    $DestinationPath = Join-Path $DestinationRoot $Name
    $Item = Get-Item -LiteralPath $SourcePath -Force

    if ($Item.PSIsContainer) {
        Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Recurse -Force
        Remove-ReleaseNoise -Root $DestinationPath
    }
    else {
        $DestinationParent = Split-Path -Path $DestinationPath -Parent
        if ($DestinationParent -and -not (Test-Path -LiteralPath $DestinationParent)) {
            New-Item -ItemType Directory -Path $DestinationParent -Force | Out-Null
        }
        Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force
    }
}

try {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    foreach ($name in $TopLevelIncludes) {
        Copy-ReleaseItem -Name $name -DestinationRoot $StagingRoot
    }

    Get-ChildItem -LiteralPath $ProjectRoot -Force -File |
        Where-Object { $_.Extension -ieq '.png' } |
        ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $StagingRoot $_.Name) -Force
        }

    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -LiteralPath $ZipPath -Force
    }

    Compress-Archive -Path (Join-Path $StagingRoot '*') -DestinationPath $ZipPath -Force

    $zipInfo = Get-Item -LiteralPath $ZipPath
    Write-Host ''
    Write-Host '========================================'
    Write-Host 'OnAuth source release packaging complete'
    Write-Host "Output file: $ZipPath"
    Write-Host "File size: $([Math]::Round($zipInfo.Length / 1MB, 2)) MB"
    Write-Host 'Excluded: .git / .venv / db / certs / cache / packaging scripts'
    Write-Host '========================================'
}
finally {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force
    }
}

