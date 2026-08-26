<#
    Проставляет описания релизов на GitHub из CHANGELOG.md и, если релиза
    для текущей версии ещё нет, создаёт его вместе с приложенным exe.

    Токен нигде не хранится и никуда не пишется: скрипт спрашивает его у
    того же диспетчера учётных данных Windows, которым пользуется git push.

    Запуск из корня проекта:
        powershell -ExecutionPolicy Bypass -File tools\publish_notes.ps1
    Посмотреть, что будет сделано, ничего не меняя:
        powershell -ExecutionPolicy Bypass -File tools\publish_notes.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Owner = "LEGionWAR7",
    [string]$Repo  = "RuFreedom",
    [switch]$Force,         # перезаписывать описания, которые уже не пусты
    [switch]$Existing       # только заполнить описания; новых релизов не создавать
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# --- токен из диспетчера учётных данных ------------------------------------
$ask = "protocol=https`nhost=github.com`n`n"
$out = $ask | git credential fill
if (-not $out) { throw "git credential fill ничего не вернул" }
$token = ($out | Where-Object { $_ -like "password=*" }) -replace "^password=", ""
if (-not $token) { throw "в учётных данных нет пароля/токена для github.com" }
$headers = @{
    Authorization          = "Bearer $token"
    "User-Agent"           = "$Repo-publish"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

# --- разбор CHANGELOG.md ----------------------------------------------------
$notes = @{}
$cur = $null
$buf = New-Object System.Collections.Generic.List[string]
foreach ($line in (Get-Content (Join-Path $root "CHANGELOG.md") -Encoding UTF8)) {
    if ($line -match '^##\s+v?(\d+(?:\.\d+)+)') {
        if ($cur) { $notes[$cur] = ($buf -join "`n").Trim() }
        $cur = $Matches[1]
        $buf.Clear()
    } elseif ($cur) {
        $buf.Add($line)
    }
}
if ($cur) { $notes[$cur] = ($buf -join "`n").Trim() }
Write-Host "В журнале описано версий: $($notes.Count)"

# --- версия текущей сборки --------------------------------------------------
$verLine = Select-String -Path (Join-Path $root "dpi\update.py") -Pattern '^VERSION\s*=\s*"([^"]+)"'
$version = $verLine.Matches[0].Groups[1].Value
Write-Host "Текущая версия: $version"

# --- что уже есть на GitHub -------------------------------------------------
$rels = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases" -Headers $headers
$seen = @{}
foreach ($r in $rels) { $seen[($r.tag_name -replace '^v', '')] = $r }

foreach ($v in ($notes.Keys | Sort-Object { [version]$_ } -Descending)) {
    $body = $notes[$v]
    $rel = $seen[$v]
    if ($rel) {
        if ($rel.body -and -not $Force) {
            Write-Host "  v$v — описание уже есть, пропускаю"
            continue
        }
        if ($PSCmdlet.ShouldProcess("v$v", "проставить описание")) {
            $payload = @{ name = "v$v"; body = $body } | ConvertTo-Json -Depth 3
            $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
            Invoke-RestMethod -Method Patch -Headers $headers -ContentType "application/json; charset=utf-8" `
                -Uri "https://api.github.com/repos/$Owner/$Repo/releases/$($rel.id)" -Body $bytes | Out-Null
            Write-Host "  v$v — описание проставлено"
        }
    } elseif ($v -eq $version -and -not $Existing) {
        if ($PSCmdlet.ShouldProcess("v$v", "создать релиз")) {
            $payload = @{ tag_name = "v$v"; name = "v$v"; body = $body } | ConvertTo-Json -Depth 3
            $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
            $rel = Invoke-RestMethod -Method Post -Headers $headers -ContentType "application/json; charset=utf-8" `
                -Uri "https://api.github.com/repos/$Owner/$Repo/releases" -Body $bytes
            Write-Host "  v$v — релиз создан"
        }
    } else {
        Write-Host "  v$v — релиза ещё нет; не трогаю"
        continue
    }

    # exe прикладываем только к релизу текущей версии
    if ($v -eq $version -and $rel) {
        $exe = Join-Path $root "dist\$Repo.exe"
        if (-not (Test-Path $exe)) {
            Write-Warning "  $exe не найден — приложить нечего"
        } elseif ($rel.assets | Where-Object { $_.name -eq "$Repo.exe" }) {
            Write-Host "  v$v — exe уже приложен"
        } elseif ($PSCmdlet.ShouldProcess("v$v", "приложить $Repo.exe")) {
            $up = "https://uploads.github.com/repos/$Owner/$Repo/releases/$($rel.id)/assets?name=$Repo.exe"
            Invoke-RestMethod -Method Post -Headers $headers -ContentType "application/octet-stream" `
                -Uri $up -InFile $exe | Out-Null
            Write-Host "  v$v — exe приложен"
        }
    }
}
Write-Host "Готово."
