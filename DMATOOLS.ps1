[CmdletBinding()]
param()

# ── Privilege check ───────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script requires Administrator privileges.' -ForegroundColor Red
    Write-Host 'Please re-run from an elevated PowerShell session.' -ForegroundColor Yellow
    exit 1
}

$ProgressPreference = 'SilentlyContinue'

# ── Required Assemblies & Connection Optimizations ───────────────────────────
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12, Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}
[System.Net.ServicePointManager]::DefaultConnectionLimit = 64
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::UseNagleAlgorithm = $false

# ── ANSI palette ──────────────────────────────────────────────────────────────
$e = [char]27

$White       = "${e}[38;2;245;245;245m"
$Grey        = "${e}[38;2;190;190;190m"
$Gray        = "${e}[38;2;125;125;125m"

$Green       = "${e}[38;2;80;220;80m"
$Red         = "${e}[91m"

$Reset       = "${e}[0m"
$Bold        = "${e}[1m"

# ── Tool groups ───────────────────────────────────────────────────────────────
$Groups = [ordered]@{
    'DMA Forensics' = @(
        'https://github.com/YasasinTurkiye/1./archive/refs/tags/DMATOOLS.zip'
    )
}


# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-OutputFolder {
    $folder = "C:\DMA Forensics"
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
    return $folder
}

function Get-FilenameFromUrl {
    param(
        [string]$Url,
        [System.Net.Http.HttpResponseMessage]$Response = $null
    )

    # 1. Prefer Content-Disposition header if available
    if ($Response -and $Response.Content.Headers.ContentDisposition -and -not [string]::IsNullOrWhiteSpace($Response.Content.Headers.ContentDisposition.FileName)) {
        return $Response.Content.Headers.ContentDisposition.FileName.Trim('"')
    }

    # 2. Check final redirected URI
    if ($Response -and $Response.RequestMessage -and $Response.RequestMessage.RequestUri) {
        $finalPath = $Response.RequestMessage.RequestUri.AbsolutePath
        $finalName = [System.Uri]::UnescapeDataString([System.IO.Path]::GetFileName($finalPath))
        if (-not [string]::IsNullOrWhiteSpace($finalName) -and [System.IO.Path]::HasExtension($finalName)) {
            return $finalName
        }
    }

    # 3. Extract from URL path
    $path = ([System.Uri]$Url).AbsolutePath
    return [System.Uri]::UnescapeDataString([System.IO.Path]::GetFileName($path))
}

# ── Fast sequential HTTP client ───────────────────────────────────────────────
$HttpHandler = [System.Net.Http.HttpClientHandler]::new()
try {
    $HttpHandler.AutomaticDecompression = [System.Net.DecompressionMethods]'GZip, Deflate'
} catch {
    $HttpHandler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip
}

# Reuse the same connection/client across all sequential downloads (HTTP Keep-Alive pool)
$HttpClient = [System.Net.Http.HttpClient]::new($HttpHandler)
$HttpClient.Timeout = [TimeSpan]::FromMinutes(10)
$HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('DMA-Forensics-Downloader/2.0')
$HttpClient.DefaultRequestHeaders.ConnectionClose = $false

# 256 KB buffer for high-throughput stream writes
$BufferSize = 262144

function Invoke-FileDownload {
    param(
        [string]$Url,
        [string]$GroupFolder,
        [System.Collections.Generic.List[string]]$FailedList
    )

    $targetFile = $null

    $filename = Get-FilenameFromUrl -Url $Url
    if ([string]::IsNullOrWhiteSpace($filename)) {
        Write-Host "    ${Red}✗ URL has no downloadable filename: $Url${Reset}"
        $FailedList.Add($Url)
        return
    }

    Write-Host "    ${Grey}↓ $filename${Reset} " -NoNewline

    try {
        # Stream response headers without buffering entire payload into RAM
        $response = $HttpClient.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        [void]$response.EnsureSuccessStatusCode()

        $betterName = Get-FilenameFromUrl -Url $Url -Response $response
        if (-not [string]::IsNullOrWhiteSpace($betterName)) {
            $filename = $betterName
        }

        $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($filename)
        $extension = [System.IO.Path]::GetExtension($filename)
        $destPath  = Join-Path $GroupFolder $filename

        # Avoid overwriting another tool with the same filename.
        $n = 2
        while (Test-Path $destPath) {
            $destPath = Join-Path $GroupFolder ("{0}_{1}{2}" -f $baseName, $n, $extension)
            $n++
        }
        $targetFile = $destPath

        # Direct native stream copy to disk
        $fileStream = [System.IO.FileStream]::new($destPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, $BufferSize, [System.IO.FileOptions]::SequentialScan)
        try {
            $netStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $netStream.CopyTo($fileStream, $BufferSize)
            Write-Host "${Green}✓${Reset}"
        } finally {
            $fileStream.Dispose()
            if ($netStream) { $netStream.Dispose() }
            $response.Dispose()
        }
    } catch {
        Write-Host "${Red}✗${Reset}"
        $FailedList.Add($Url)
        if ($targetFile -and (Test-Path $targetFile)) { Remove-Item -Path $targetFile -Force -ErrorAction SilentlyContinue }
    }
}

function Show-Banner {
    Clear-Host

    Write-Host "${White} ███████╗████████╗ █████╗ ██████╗ ███████╗ ${Reset}"
    Write-Host "${White} ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ${Reset}"
    Write-Host "${White} ███████╗   ██║   ███████║██████╔╝███████╗ ${Reset}"
    Write-Host "${White} ╚════██║   ██║   ██╔══██║██╔══██╗╚════██║ ${Reset}"
    Write-Host "${White} ███████║   ██║   ██║  ██║██║  ██║███████║ ${Reset}"
    Write-Host "${White} ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ${Reset}"
    Write-Host ""
    Write-Host "${Gray}   DMA Forensics${Reset}"
    Write-Host "${White}  ━━━━━━━━━━━━${Reset}"
    Write-Host ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
Show-Banner

$OutputFolder = Get-OutputFolder
$totalTools   = ($Groups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

Write-Host "  ${White}Output folder  ${Gray}$OutputFolder${Reset}"
Write-Host "  ${Gray}Total tools    ${White}$totalTools${Reset} ${Gray}across $($Groups.Count) groups${Reset}"
Write-Host ""

# ── Download mode prompt ──────────────────────────────────────────────────────
Write-Host "  ${White}Download mode:${Reset}"
Write-Host ""
Write-Host "    ${Grey}[A]${Gray}  All tools ${Gray}($totalTools files)${Reset}"
Write-Host "    ${Grey}[C]${Gray}  Choose specific groups${Reset}"
Write-Host ""
$mode = (Read-Host "  >").Trim().ToUpper()

[string[]]$selectedNames = @()

if ($mode -eq 'A') {
    $selectedNames = @($Groups.Keys)
} elseif ($mode -eq 'C') {
    Write-Host ""
    $groupKeys = @($Groups.Keys)
    Write-Host "  ${White}Available groups:${Reset}"
    Write-Host ""
    for ($i = 0; $i -lt $groupKeys.Count; $i++) {
        $cnt = $Groups[$groupKeys[$i]].Count
        Write-Host "    ${Gray}[$($i + 1)]${Gray} $($groupKeys[$i]) ${Gray}($cnt tools)${Reset}"
    }
    Write-Host ""
    Write-Host "  ${White}Enter group numbers separated by commas ${Gray}(e.g. 1,3,5)${Grey}:${Reset}"
    $raw = (Read-Host "  >").Trim()

    foreach ($part in ($raw -split ',')) {
        $part = $part.Trim()
        if ($part -match '^\d+$') {
            $idx = [int]$part - 1
            if ($idx -ge 0 -and $idx -lt $groupKeys.Count) {
                $selectedNames += $groupKeys[$idx]
            }
        }
    }

    if ($selectedNames.Count -eq 0) {
        Write-Host ""
        Write-Host "  ${Red}No valid groups selected. Exiting.${Reset}"
        exit 0
    }
} else {
    Write-Host ""
    Write-Host "  ${Red}Invalid choice. Exiting.${Reset}"
    exit 0
}

# ── Confirmation ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${White}Selected groups:${Reset}"
Write-Host ""
$totalSelected = 0
foreach ($name in $selectedNames) {
    $cnt = $Groups[$name].Count
    $totalSelected += $cnt
    Write-Host "    ${Grey}• $name ${Gray}($cnt tools)${Reset}"
}
Write-Host ""
Write-Host "  ${White}Files to download: ${Grey}$totalSelected${Reset}"
Write-Host ""
$confirm = (Read-Host "  ${Grey}Proceed? [Y/N]  >${Reset}").Trim().ToUpper()
if ($confirm -ne 'Y') {
    Write-Host ""
    Write-Host "  ${Red}Aborted.${Reset}"
    exit 0
}

# ── Setup output folder ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ${White}Creating ${Grey}$OutputFolder${White}...${Reset}" -NoNewline
$null = New-Item -ItemType Directory -Path $OutputFolder -Force
Write-Host " ${Green}✓${Reset}"

# ── Download ──────────────────────────────────────────────────────────────────
$failed = [System.Collections.Generic.List[string]]::new()

foreach ($groupName in $selectedNames) {
    $urls = $Groups[$groupName]

    Write-Host ""
    Write-Host "  ${White}━━━ $groupName ${Gray}($($urls.Count) tools)${Reset}"
    Write-Host ""

    # Files go directly into C:\DMA Forensics (no per-group subfolder)
    foreach ($url in $urls) {
        Invoke-FileDownload -Url $url -GroupFolder $OutputFolder -FailedList $failed
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
$succeeded = $totalSelected - $failed.Count

Write-Host ""
Write-Host "  ${White}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host "  ${Green}✓ Downloaded : $succeeded / $totalSelected${Reset}"

if ($failed.Count -gt 0) {
    Write-Host "  ${Red}✗ Failed     : $($failed.Count)${Reset}"
    Write-Host ""
    Write-Host "  ${Red}Failed URLs:${Reset}"

    foreach ($f in $failed) {
        Write-Host "    ${Gray}$f${Reset}"
    }
}

Write-Host ""
Write-Host "  ${White}Tools saved to ${Grey}$OutputFolder${Reset}"
Write-Host "  ${Grey}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host ""
