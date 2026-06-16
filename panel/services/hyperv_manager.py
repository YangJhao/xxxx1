"""Small Hyper-V management wrapper for the web panel."""
import json
import locale
import os
import platform
import subprocess
import re


POWERSHELL = "powershell.exe"
ACTION_COMMANDS = {
    "start": "Start-VM -Name $name",
    "shutdown": "Stop-VM -Name $name -Force",
    "turnoff": "Stop-VM -Name $name -TurnOff -Force",
    "restart": "Restart-VM -Name $name -Force",
    "reset": "Reset-VM -Name $name -Force",
    "save": "Save-VM -Name $name",
}


def _run_ps(script: str, timeout: int = 30):
    if platform.system().lower() != "windows":
        raise RuntimeError("Hyper-V management is only available on Windows hosts.")

    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding=locale.getpreferredencoding(False),
        errors="replace",
    )
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(_friendly_error(err) or f"PowerShell exited with {completed.returncode}")
    return completed.stdout.strip()


def _friendly_error(text: str):
    text = text or ""
    if "InvalidState" in text or "InvalidStateException" in text:
        return "虚拟机正在运行，CPU/内存等硬件配置需要先关机后才能修改。"
    if "NamedParameterNotFound" in text and "Stop-VM" in text:
        return "关机命令参数不兼容，已修正为当前 Hyper-V 支持的关机方式，请刷新后重试。"
    if "The operation cannot be performed while the object is in its current state" in text:
        return "当前虚拟机状态不允许执行这个操作，请刷新状态后再试。"
    if "Failed to stop" in text or "Stop-VM" in text:
        return "虚拟机关机失败。可以先尝试正常关机；如果系统无响应，再使用强制断电。"
    if "Set-VMProcessor" in text:
        return "CPU 配置修改失败，请确认虚拟机已关机。"
    if "Set-VMMemory" in text:
        return "内存配置修改失败，请确认虚拟机已关机，且内存范围填写正确。"
    if "Hyper-V" in text and ("not recognized" in text or "无法将" in text):
        return "当前主机没有可用的 Hyper-V PowerShell 管理模块。"
    return text


def _json_ps(script: str, timeout: int = 30):
    output = _run_ps(script, timeout=timeout)
    if not output:
        return []
    return json.loads(output)


def list_vms():
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$vms = Get-VM | Sort-Object Name | ForEach-Object {
  $cpu = $null
  $adapters = @()
  $ips = @()
  try { $cpu = Get-VMMemory -VMName $_.Name } catch {}
  try {
    $adapters = @(Get-VMNetworkAdapter -VMName $_.Name)
    $ips = @($adapters | ForEach-Object { $_.IPAddresses } | Where-Object { $_ -and $_ -notmatch ':' })
  } catch {}
  $privateIps = @($ips | Where-Object { $_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)' })
  $publicIps = @($ips | Where-Object { $_ -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|127\.)' })
  [pscustomobject]@{
    name = $_.Name
    state = $_.State.ToString()
    status = $_.Status
    public_ip = ($publicIps -join ', ')
    internal_ip = ($privateIps -join ', ')
    mac = (($adapters | ForEach-Object {$_.MacAddress}) -join ', ')
    switch_name = (($adapters | ForEach-Object {$_.SwitchName}) -join ', ')
    uptime = $_.Uptime.ToString()
    cpu_usage = $_.CPUUsage
    memory_assigned = $_.MemoryAssigned
    memory_startup = $_.MemoryStartup
    memory_demand = if ($cpu) { $cpu.Demand } else { $null }
    processor_count = $_.ProcessorCount
    automatic_start_action = $_.AutomaticStartAction.ToString()
    automatic_stop_action = $_.AutomaticStopAction.ToString()
    generation = $_.Generation
    version = $_.Version.ToString()
  }
}
$vms | ConvertTo-Json -Depth 4
"""
    data = _json_ps(script)
    if isinstance(data, dict):
        return [data]
    return data or []


def get_vm_config(name: str):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
$mem = Get-VMMemory -VMName $name
[pscustomobject]@{{
  name = $vm.Name
  state = $vm.State.ToString()
  processor_count = $vm.ProcessorCount
  memory_startup_mb = [int]($mem.Startup / 1MB)
  dynamic_memory_enabled = [bool]$mem.DynamicMemoryEnabled
  memory_minimum_mb = [int]($mem.Minimum / 1MB)
  memory_maximum_mb = [int]($mem.Maximum / 1MB)
  automatic_start_action = $vm.AutomaticStartAction.ToString()
  automatic_stop_action = $vm.AutomaticStopAction.ToString()
  notes = $vm.Notes
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script)


def host_summary():
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$vms = @(Get-VM)
$hostInfo = Get-VMHost
$summary = [pscustomobject]@{
  computer_name = $env:COMPUTERNAME
  total = $vms.Count
  running = @($vms | Where-Object {$_.State -eq 'Running'}).Count
  off = @($vms | Where-Object {$_.State -eq 'Off'}).Count
  paused = @($vms | Where-Object {$_.State -eq 'Paused'}).Count
  saved = @($vms | Where-Object {$_.State -eq 'Saved'}).Count
  virtual_hard_disk_path = $hostInfo.VirtualHardDiskPath
  virtual_machine_path = $hostInfo.VirtualMachinePath
}
$summary | ConvertTo-Json -Depth 4
"""
    return _json_ps(script)


def list_switches():
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Get-VMSwitch | Sort-Object Name | ForEach-Object {
  [pscustomobject]@{
    name = $_.Name
    switch_type = $_.SwitchType.ToString()
    net_adapter = $_.NetAdapterInterfaceDescription
  }
} | ConvertTo-Json -Depth 4
"""
    data = _json_ps(script)
    if isinstance(data, dict):
        return [data]
    return data or []


def list_images():
    script = r"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$hostInfo = Get-VMHost
$paths = @()
if ($hostInfo.VirtualHardDiskPath) { $paths += $hostInfo.VirtualHardDiskPath }
$paths += 'C:\HyperV'
$paths += 'C:\HyperV\VHDs'
$paths += 'C:\42IPwin\images'
$paths = $paths | Select-Object -Unique
$rows = @()
foreach ($p in $paths) {
  if (-not (Test-Path $p)) { continue }
  $rows += Get-ChildItem -Path $p -Recurse -File -Include *.vhd,*.vhdx,*.iso -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
      name = $_.Name
      path = $_.FullName
      size = $_.Length
      extension = $_.Extension.ToLower()
      updated_at = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
  }
}
$rows | Sort-Object updated_at -Descending | ConvertTo-Json -Depth 4
"""
    data = _json_ps(script, timeout=60)
    if isinstance(data, dict):
        return [data]
    return data or []


def import_image(source_path: str):
    source_path = (source_path or "").strip().strip('"')
    if not source_path:
        raise ValueError("Image path is required.")
    if not source_path.lower().endswith((".vhd", ".vhdx", ".iso")):
        raise ValueError("Only .vhd, .vhdx, and .iso images are supported.")

    script = rf"""
$ErrorActionPreference = 'Stop'
$source = {json.dumps(source_path)}
if (-not (Test-Path $source)) {{ throw '镜像文件不存在。' }}
$destDir = 'C:\42IPwin\images'
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
$dest = Join-Path $destDir (Split-Path $source -Leaf)
if ((Resolve-Path $source).Path -ne $dest) {{
  Copy-Item -Force -Path $source -Destination $dest
}}
$item = Get-Item $dest
[pscustomobject]@{{
  name = $item.Name
  path = $item.FullName
  size = $item.Length
  extension = $item.Extension.ToLower()
  updated_at = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=600)


def vm_action(name: str, action: str):
    name = (name or "").strip()
    action = (action or "").strip().lower()
    if not name:
        raise ValueError("VM name is required.")
    if action not in ACTION_COMMANDS:
        raise ValueError("Unsupported VM action.")

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
{ACTION_COMMANDS[action]}
Start-Sleep -Milliseconds 600
$fresh = Get-VM -Name $name
[pscustomobject]@{{
  name = $fresh.Name
  state = $fresh.State.ToString()
  status = $fresh.Status
  uptime = $fresh.Uptime.ToString()
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=60)


def update_vm_config(name: str, data: dict):
    name = (name or "").strip()
    if not name:
        raise ValueError("VM name is required.")

    processor_count = int(data.get("processor_count") or 0)
    memory_startup_mb = int(data.get("memory_startup_mb") or 0)
    dynamic_memory_enabled = bool(data.get("dynamic_memory_enabled"))
    memory_minimum_mb = int(data.get("memory_minimum_mb") or memory_startup_mb)
    memory_maximum_mb = int(data.get("memory_maximum_mb") or memory_startup_mb)
    start_action = (data.get("automatic_start_action") or "Nothing").strip()
    stop_action = (data.get("automatic_stop_action") or "Save").strip()
    notes = data.get("notes") or ""

    if processor_count < 1 or processor_count > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_startup_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if memory_minimum_mb < 32 or memory_maximum_mb < memory_minimum_mb:
        raise ValueError("Invalid dynamic memory range.")
    if start_action not in {"Nothing", "StartIfRunning", "Start"}:
        raise ValueError("Invalid automatic start action.")
    if stop_action not in {"Save", "TurnOff", "ShutDown"}:
        raise ValueError("Invalid automatic stop action.")

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$name = {json.dumps(name)}
$vm = Get-VM -Name $name
$mem = Get-VMMemory -VMName $name
$hardwareChanged = $false
if ($vm.ProcessorCount -ne {processor_count}) {{ $hardwareChanged = $true }}
if ([int]($mem.Startup / 1MB) -ne {memory_startup_mb}) {{ $hardwareChanged = $true }}
if ([bool]$mem.DynamicMemoryEnabled -ne ${str(dynamic_memory_enabled).lower()}) {{ $hardwareChanged = $true }}
if ([int]($mem.Minimum / 1MB) -ne {memory_minimum_mb}) {{ $hardwareChanged = $true }}
if ([int]($mem.Maximum / 1MB) -ne {memory_maximum_mb}) {{ $hardwareChanged = $true }}
$hardwareSkipped = $false
if ($hardwareChanged -and $vm.State -eq 'Off') {{
  Set-VMProcessor -VMName $name -Count {processor_count}
  Set-VMMemory -VMName $name -StartupBytes ({memory_startup_mb}MB) -DynamicMemoryEnabled ${str(dynamic_memory_enabled).lower()} -MinimumBytes ({memory_minimum_mb}MB) -MaximumBytes ({memory_maximum_mb}MB)
}} elseif ($hardwareChanged) {{
  $hardwareSkipped = $true
}}
Set-VM -Name $name -AutomaticStartAction {start_action} -AutomaticStopAction {stop_action} -Notes {json.dumps(notes)}
$fresh = Get-VM -Name $name
$freshMem = Get-VMMemory -VMName $name
[pscustomobject]@{{
  name = $fresh.Name
  state = $fresh.State.ToString()
  processor_count = $fresh.ProcessorCount
  memory_startup = $fresh.MemoryStartup
  memory_startup_mb = [int]($freshMem.Startup / 1MB)
  hardware_skipped = $hardwareSkipped
  message = if ($hardwareSkipped) {{ 'CPU/内存硬件配置未修改：请先关闭虚拟机后再保存硬件配置。' }} else {{ '' }}
  automatic_start_action = $fresh.AutomaticStartAction.ToString()
  automatic_stop_action = $fresh.AutomaticStopAction.ToString()
}} | ConvertTo-Json -Depth 4
"""
    return _json_ps(script, timeout=60)


def batch_action(names, action: str):
    names = [str(x).strip() for x in (names or []) if str(x).strip()]
    if not names:
        raise ValueError("No VMs selected.")
    action = (action or "").strip().lower()
    if action == "reset_password":
        raise RuntimeError("Hyper-V cannot reset guest OS passwords directly. Configure a guest script/agent or provide guest credentials first.")
    if action not in ACTION_COMMANDS:
        raise ValueError("Unsupported VM action.")

    results = []
    for name in names:
        try:
            results.append({"name": name, "ok": True, "data": vm_action(name, action)})
        except Exception as exc:
            results.append({"name": name, "ok": False, "error": str(exc)})
    return results


def batch_create_vms(data: dict):
    prefix = (data.get("prefix") or "hy").strip()
    count = int(data.get("count") or 0)
    start_index = int(data.get("start_index") or 1)
    processor_count = int(data.get("processor_count") or 1)
    memory_startup_mb = int(data.get("memory_startup_mb") or 1024)
    disk_size_gb = int(data.get("disk_size_gb") or 20)
    generation = int(data.get("generation") or 2)
    switch_name = (data.get("switch_name") or "").strip()
    image_path = (data.get("image_path") or "").strip()
    auto_start = bool(data.get("auto_start"))

    if not prefix:
        raise ValueError("Name prefix is required.")
    if count < 1 or count > 200:
        raise ValueError("Create count must be between 1 and 200.")
    if processor_count < 1 or processor_count > 64:
        raise ValueError("CPU count must be between 1 and 64.")
    if memory_startup_mb < 128:
        raise ValueError("Startup memory must be at least 128 MB.")
    if disk_size_gb < 1 or disk_size_gb > 2048:
        raise ValueError("Disk size must be between 1 and 2048 GB.")
    if generation not in {1, 2}:
        raise ValueError("VM generation must be 1 or 2.")

    names = [f"{prefix}-{i:03d}" for i in range(start_index, start_index + count)]
    names_json = json.dumps(names, ensure_ascii=False)
    switch_json = json.dumps(switch_name, ensure_ascii=False)
    image_json = json.dumps(image_path, ensure_ascii=False)

    script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
$names = ConvertFrom-Json @'
{names_json}
'@
$switchName = {switch_json}
$imagePath = {image_json}
$hostInfo = Get-VMHost
$vmRoot = $hostInfo.VirtualMachinePath
$vhdRoot = $hostInfo.VirtualHardDiskPath
if (-not $vmRoot) {{ $vmRoot = 'C:\HyperV\VMs' }}
if (-not $vhdRoot) {{ $vhdRoot = 'C:\HyperV\VHDs' }}
New-Item -ItemType Directory -Force -Path $vmRoot,$vhdRoot | Out-Null
if ($imagePath -and -not (Test-Path $imagePath)) {{ throw '选择的镜像文件不存在。' }}
$results = @()
foreach ($name in $names) {{
  try {{
    if (Get-VM -Name $name -ErrorAction SilentlyContinue) {{
      $results += [pscustomobject]@{{ name=$name; ok=$false; error='虚拟机名称已存在' }}
      continue
    }}
    $vhdPath = Join-Path $vhdRoot ($name + '.vhdx')
    if (Test-Path $vhdPath) {{
      $results += [pscustomobject]@{{ name=$name; ok=$false; error='虚拟硬盘文件已存在' }}
      continue
    }}
    $args = @{{ Name = $name; Generation = {generation}; MemoryStartupBytes = ({memory_startup_mb}MB); Path = $vmRoot }}
    if ($imagePath -and ($imagePath.ToLower().EndsWith('.vhd') -or $imagePath.ToLower().EndsWith('.vhdx'))) {{
      Copy-Item -Force -Path $imagePath -Destination $vhdPath
      $args.VHDPath = $vhdPath
    }} else {{
      $args.NewVHDPath = $vhdPath
      $args.NewVHDSizeBytes = ({disk_size_gb}GB)
    }}
    if ($switchName) {{ $args.SwitchName = $switchName }}
    New-VM @args | Out-Null
    if ($imagePath -and $imagePath.ToLower().EndsWith('.iso')) {{
      Add-VMDvdDrive -VMName $name -Path $imagePath
    }}
    Set-VMProcessor -VMName $name -Count {processor_count}
    Set-VM -Name $name -AutomaticStopAction ShutDown
    if (${str(auto_start).lower()}) {{ Start-VM -Name $name }}
    $fresh = Get-VM -Name $name
    $results += [pscustomobject]@{{ name=$name; ok=$true; state=$fresh.State.ToString(); vhd=$vhdPath }}
  }} catch {{
    $results += [pscustomobject]@{{ name=$name; ok=$false; error=$_.Exception.Message }}
  }}
}}
$results | ConvertTo-Json -Depth 4
"""
    result = _json_ps(script, timeout=max(90, count * 8))
    if isinstance(result, dict):
        return [result]
    return result or []
