param(
    [string]$Target = "C:\42IPwin"
)

$ErrorActionPreference = "Stop"
$source = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $Target)) {
    throw "Target path not found: $Target"
}

$files = @(
    "panel\app.py",
    "panel\routes\hyperv.py",
    "panel\services\hyperv_manager.py",
    "panel\templates\base.html",
    "panel\templates\hyperv.html",
    "panel\static\css\app.css"
)

foreach ($file in $files) {
    $src = Join-Path $source $file
    $dst = Join-Path $Target $file
    if (-not (Test-Path $src)) {
        throw "Missing source file: $src"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
    Copy-Item -Force -Path $src -Destination $dst
}

Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Process -FilePath "python.exe" -ArgumentList @("panel\app.py", "--no-browser") -WorkingDirectory $Target -WindowStyle Hidden

Write-Host "Hyper-V module installed. Open: http://127.0.0.1:8080/hyperv"
