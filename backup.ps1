$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$backupDirectory = Join-Path $projectRoot 'backups'
$containerBackup = '/tmp/medconnect-backup.db'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupFile = Join-Path $backupDirectory "medconnect-$timestamp.db"

New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
docker compose exec -T app python -c "import os, sqlite3; path='$containerBackup'; os.path.exists(path) and os.remove(path); source=sqlite3.connect('/data/medconnect.db'); backup=sqlite3.connect(path); source.backup(backup); backup.close(); source.close()"
if ($LASTEXITCODE -ne 0) {
    throw 'Could not create a consistent SQLite backup.'
}

docker compose cp "app:$containerBackup" $backupFile
if ($LASTEXITCODE -ne 0) {
    throw 'Could not copy the SQLite backup to the host.'
}

docker compose exec -T app python -c "import os; os.remove('$containerBackup')"
if ($LASTEXITCODE -ne 0) {
    throw 'The backup was created, but its temporary container copy could not be removed.'
}

Get-ChildItem -Path $backupDirectory -File -Filter 'medconnect-*.db' |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force

Write-Output "Backup created: $backupFile"
