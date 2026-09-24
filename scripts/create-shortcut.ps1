param([string]$Executable)
$ErrorActionPreference = 'Stop'
$connectRoot = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $connectRoot 'dist\win-x64\Eclipse Connect.exe' }
$connectExe = (Resolve-Path -LiteralPath $Executable).Path
if (-not $connectExe.StartsWith($connectRoot + '\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($connectExe) -ne 'Eclipse Connect.exe') { throw 'Unexpected executable target' }
$connectDesktop = [Environment]::GetFolderPath('DesktopDirectory')
$connectShortcutPath = Join-Path $connectDesktop 'Eclipse Connect.lnk'
$connectShell = New-Object -ComObject WScript.Shell
$connectShortcut = $connectShell.CreateShortcut($connectShortcutPath)
if ((Test-Path -LiteralPath $connectShortcutPath) -and -not $connectShortcut.TargetPath.StartsWith($connectRoot + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'An unrelated shortcut already uses this name' }
$connectShortcut.TargetPath = $connectExe
$connectShortcut.WorkingDirectory = [IO.Path]::GetDirectoryName($connectExe)
$connectShortcut.IconLocation = $connectExe + ',0'
$connectShortcut.Description = 'Telegram, FIX и проверка доступа'
$connectShortcut.Save()
Write-Output ('Shortcut: ' + $connectShortcutPath)
