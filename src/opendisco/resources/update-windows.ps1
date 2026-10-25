# Finish an OpenDisco update on Windows. The app (opendisco/update.py) starts this just before it
# quits, from the folder the new version's setup.exe was downloaded to: it waits for the app to
# quit, runs the installer silently over the same install folder, and opens the app again. A copy
# of the previous version's files is kept until the installer has finished, and put back if it fails.
param([int]$AppPid, [string]$Setup, [string]$Dir, [string]$Log)
$ErrorActionPreference = 'Stop'
function Say($text) { Add-Content -Path $Log -Value "$(Get-Date -Format 'HH:mm:ss')  $text" }
$parts = 'python', 'app'

try {
    Say "Waiting for OpenDisco (process $AppPid) to quit"
    Wait-Process -Id $AppPid -Timeout 120 -ErrorAction SilentlyContinue
    # Another copy of the app (or its command-line tool) running from the folder holds files open.
    $deadline = (Get-Date).AddSeconds(30)
    while (Get-Process -ErrorAction SilentlyContinue |
           Where-Object { $_.Path -and $_.Path.StartsWith("$Dir\", [StringComparison]::OrdinalIgnoreCase) }) {
        if ((Get-Date) -gt $deadline) { throw 'OpenDisco is still running in another window: close it and update again' }
        Start-Sleep -Milliseconds 500
    }
    $backup = Join-Path (Split-Path -Parent $Setup) 'previous'
    Say "Copying the current version to $backup"
    New-Item -ItemType Directory -Force -Path $backup | Out-Null
    foreach ($part in $parts) {
        if (Test-Path -LiteralPath "$Dir\$part") { Copy-Item -Recurse -Force -LiteralPath "$Dir\$part" -Destination $backup }
    }
    Say "Running $Setup"
    # /D= must come last and unquoted, even with spaces in the path (NSIS reads to the end).
    $run = Start-Process -FilePath $Setup -ArgumentList "/S /D=$Dir" -Wait -PassThru
    if ($run.ExitCode -ne 0) {
        Say "The installer stopped with exit code $($run.ExitCode): putting the previous version back"
        foreach ($part in $parts) {
            if (Test-Path -LiteralPath "$backup\$part") {
                if (Test-Path -LiteralPath "$Dir\$part") { Remove-Item -Recurse -Force -LiteralPath "$Dir\$part" }
                Copy-Item -Recurse -Force -LiteralPath "$backup\$part" -Destination $Dir
            }
        }
    } else {
        Say 'Installed'
    }
} catch {
    Say "Failed: $_"
}
Start-Process -FilePath "$Dir\python\pythonw.exe" -ArgumentList '-m', 'opendisco' -WorkingDirectory $Dir
