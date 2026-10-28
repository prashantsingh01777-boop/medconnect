$ErrorActionPreference = 'Stop'

$python = (Get-Command python -ErrorAction Stop).Source
$cloudflared = (Get-Command cloudflared -ErrorAction Stop).Source
$logDirectory = Join-Path $env:LOCALAPPDATA 'MedConnect\logs'
$backendLog = Join-Path $logDirectory 'backend.log'
$tunnelLog = Join-Path $logDirectory 'cloudflared.log'
$tunnelErrorLog = Join-Path $logDirectory 'cloudflared-error.log'
$supervisorLog = Join-Path $logDirectory 'supervisor.log'

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$env:HOST = '127.0.0.1'
$env:PORT = '5101'

$backendProcess = $null
$tunnelProcess = $null

while ($true) {
    if (-not $backendProcess -or $backendProcess.HasExited) {
        if ($backendProcess) {
            Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Backend exited with code $($backendProcess.ExitCode); restarting."
        }
        $backendProcess = Start-Process `
            -FilePath $python `
            -ArgumentList 'app.py' `
            -WorkingDirectory $PSScriptRoot `
            -WindowStyle Hidden `
            -RedirectStandardOutput $backendLog `
            -RedirectStandardError (Join-Path $logDirectory 'backend-error.log') `
            -PassThru
    }

    if (-not $tunnelProcess -or $tunnelProcess.HasExited) {
        if ($tunnelProcess) {
            Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Cloudflared exited with code $($tunnelProcess.ExitCode); restarting."
        }
        $tunnelProcess = Start-Process `
            -FilePath $cloudflared `
            -ArgumentList @(
                'tunnel',
                '--no-autoupdate',
                '--url', 'http://127.0.0.1:5101'
            ) `
            -WindowStyle Hidden `
            -RedirectStandardOutput $tunnelLog `
            -RedirectStandardError $tunnelErrorLog `
            -PassThru
    }

    Start-Sleep -Seconds 10
}
