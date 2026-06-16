$ErrorActionPreference = 'SilentlyContinue'

$project = 'C:\42IPwin'
$python = 'C:\Program Files\Python310\python.exe'
$singBox = Join-Path $project 'sing-box\sing-box.exe'
$config = Join-Path $project 'sing-box\config.json'
$workdir = Join-Path $project 'sing-box'

$running = Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq 'sing-box.exe' -and $_.CommandLine -like '*42IPwin*config.json*' } |
  Select-Object -First 1

if ($running) {
  exit 0
}

Set-Location $project
& $python 'panel\services\cfg_generator.py' | Out-Null
& $singBox check -c $config | Out-Null
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

Start-Process -FilePath $singBox -ArgumentList 'run','-c',$config -WorkingDirectory $workdir -WindowStyle Hidden
