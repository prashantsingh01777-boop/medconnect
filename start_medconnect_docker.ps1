$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$composeFile = Join-Path $projectRoot 'compose.tunnel.yaml'
$logDirectory = Join-Path $env:LOCALAPPDATA 'MedConnect\logs'
$environmentFile = Join-Path $env:LOCALAPPDATA 'MedConnect\docker-tunnel.env'
$tunnelLog = Join-Path $logDirectory 'docker-cloudflared.log'
$tunnelErrorLog = Join-Path $logDirectory 'docker-cloudflared-error.log'
$supervisorLog = Join-Path $logDirectory 'docker-supervisor.log'

New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
$docker = if ($dockerCommand) {
    $dockerCommand.Source
} else {
    Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'
}
$cloudflaredCommand = Get-Command cloudflared -ErrorAction SilentlyContinue
$cloudflared = if ($cloudflaredCommand) {
    $cloudflaredCommand.Source
} else {
    Join-Path ${env:ProgramFiles(x86)} 'cloudflared\cloudflared.exe'
}

if (-not (Test-Path -LiteralPath $docker)) {
    Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Docker CLI was not found at $docker."
    throw "Docker CLI was not found at $docker."
}
if (-not (Test-Path -LiteralPath $cloudflared)) {
    Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Cloudflared was not found at $cloudflared."
    throw "Cloudflared was not found at $cloudflared."
}
if (-not (Test-Path -LiteralPath $environmentFile)) {
    Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Docker environment file is missing at $environmentFile."
    throw "Create $environmentFile with MEDCONNECT_SECRET_KEY and MEDCONNECT_SUPPORT_EMAIL before starting Docker."
}

$composeArguments = @(
    'compose',
    '--project-name', 'medconnect-tunnel',
    '--env-file', $environmentFile,
    '-f', $composeFile
)

function Wait-ForDockerEngine {
    $desktopPath = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'
    if (-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)) {
        if (-not (Test-Path -LiteralPath $desktopPath)) {
            throw "Docker Desktop was not found at $desktopPath."
        }
        Start-Process -FilePath $desktopPath | Out-Null
    }

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $engineOutput = & $docker info --format '{{.ServerVersion}}' 2>&1
            $engineExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($engineExitCode -eq 0) {
            return
        }
        if ($attempt % 10 -eq 0) {
            Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Waiting for Docker Engine to become available."
        }
        Start-Sleep -Seconds 5
    }
    throw 'Docker Engine did not become available within five minutes.'
}

Wait-ForDockerEngine
$previousErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $startupOutput = & $docker @composeArguments up -d --build --wait --wait-timeout 120 app 2>&1
    $startupExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousErrorActionPreference
}
$startupOutput | Add-Content -Path $supervisorLog
if ($startupExitCode -ne 0) {
    throw "Docker Compose could not start the MedConnect app (exit code $startupExitCode). See $supervisorLog."
}

$tunnelProcess = $null
while ($true) {
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $containerId = & $docker @composeArguments ps --status running --quiet app 2>$null
        $containerExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($containerExitCode -ne 0 -or -not $containerId) {
        Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Docker app is not running; attempting recovery."
        Wait-ForDockerEngine
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $recoveryOutput = & $docker @composeArguments up -d --build --wait --wait-timeout 120 app 2>&1
            $recoveryExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $recoveryOutput | Add-Content -Path $supervisorLog
        if ($recoveryExitCode -ne 0) {
            Add-Content -Path $supervisorLog -Value "$(Get-Date -Format o) Docker recovery failed with exit code $recoveryExitCode."
        }
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
                '--url', 'http://127.0.0.1:5103'
            ) `
            -WindowStyle Hidden `
            -RedirectStandardOutput $tunnelLog `
            -RedirectStandardError $tunnelErrorLog `
            -PassThru
    }

    Start-Sleep -Seconds 10
}
