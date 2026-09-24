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
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

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
$SpeedyWhite = "${e}[38;2;255;255;255m"

$Green       = "${e}[38;2;80;220;80m"
$Red         = "${e}[91m"

$Reset       = "${e}[0m"
$Bold        = "${e}[1m"

# ── Tool groups ───────────────────────────────────────────────────────────────
$Groups = [ordered]@{
    'DMA Forensics' = @(
        'https://raw.githubusercontent.com/YasasinTurkiye/1./main/Aim%20Device%20Scanner.exe'
        'https://raw.githubusercontent.com/YasasinTurkiye/1./main/DMA-multitool.exe'
        'https://raw.githubusercontent.com/YasasinTurkiye/1./main/Hash%26History%20Scanner.exe'
        'https://raw.githubusercontent.com/YasasinTurkiye/1./main/RAM%20DUMP%20Analyzer.exe'
        'https://raw.githubusercontent.com/YasasinTurkiye/1./main/Setup.Api.Dev%20Analyzer.exe'
        'https://raw.githubusercontent.com/YasasinTurkiye/1./main/TLP%20Contactor.exe'
    )
}


# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-NextSSFolder {
    $i = 1
    while (Test-Path "C:\ss$i") { $i++ }
    return "C:\ss$i"
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

    }

    # 4. Extract from URL path
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
$HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('Speedyxx-ToolsDownloader/2.0')
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
    $tempZip    = $null

    $filename = Get-FilenameFromUrl -Url $Url
    if ([string]::IsNullOrWhiteSpace($filename)) {
        Write-Host "    ${Red}✗ URL has no downloadable filename: $Url${Reset}"
        $FailedList.Add($Url)
        return
    }

    Write-Host "    ${DkOrange}↓ ${Orange}$filename${Reset} " -NoNewline

    try {
        # Stream response headers without buffering entire payload into RAM
        $response = $HttpClient.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        [void]$response.EnsureSuccessStatusCode()

        $betterName = Get-FilenameFromUrl -Url $Url -Response $response
        if (-not [string]::IsNullOrWhiteSpace($betterName)) {
            $filename = $betterName
        }

        $isZip = $filename -match '\.zip$'

        if ($isZip) {
            $baseName   = [System.IO.Path]::GetFileNameWithoutExtension($filename)
            $tempZip    = Join-Path $GroupFolder $filename
            $extractDir = Join-Path $GroupFolder $baseName

            # Avoid overwriting another tool with the same filename.
            $n = 2
            while ((Test-Path $tempZip) -or (Test-Path $extractDir)) {
                $tempZip    = Join-Path $GroupFolder ("{0}_{1}.zip" -f $baseName, $n)
                $extractDir = Join-Path $GroupFolder ("{0}_{1}" -f $baseName, $n)
                $n++
            }

            # Direct native stream copy to disk
            $fileStream = [System.IO.FileStream]::new($tempZip, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, $BufferSize, [System.IO.FileOptions]::SequentialScan)
            try {
                $netStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $netStream.CopyTo($fileStream, $BufferSize)
            } finally {
                $fileStream.Dispose()
                if ($netStream) { $netStream.Dispose() }
                $response.Dispose()
            }

            # Fast native CLR zip extraction (orders of magnitude faster than Expand-Archive)
            try {
                [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $extractDir)
                Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
                Write-Host "${Green}✓${Reset}"
            } catch {
                # Fallback to Expand-Archive if ZipFile fails on non-standard entries
                try {
                    $null = New-Item -ItemType Directory -Path $extractDir -Force
                    Expand-Archive -Path $tempZip -DestinationPath $extractDir -Force
                    Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
                    Write-Host "${Green}✓${Reset}"
                } catch {
                    Write-Host "${Red}✗${Reset}"
                    $FailedList.Add($Url)
                    if (Test-Path $tempZip) { Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue }
                }
            }
        } else {
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
        }
    } catch {
        Write-Host "${Red}✗${Reset}"
        $FailedList.Add($Url)
        if ($targetFile -and (Test-Path $targetFile)) { Remove-Item -Path $targetFile -Force -ErrorAction SilentlyContinue }
        if ($tempZip -and (Test-Path $tempZip))       { Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue }
    }
}

function Show-Banner {
    Clear-Host

    $mr = $White; $mo = $Grey; $mc = $Stars; $r = $Reset
    Write-Host ""
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀"
    Write-Host " ⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀"
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀"
    Write-Host " ⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"⠀
    Write-Host "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    Write-Host "⠀⠀ ⠀✦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✧⠀⠀⠀⠀"
    Write-Host "⠀⠀⠀⠀⋆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀✦⠀⠀"
     Write-Host ""
    # STARS wordmark
    Write-Host "${White}${Grey} ███████╗████████╗ █████╗ ██████╗ ███████╗ ${Reset}"
    Write-Host "${White}${Grey} ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝ ${Reset}"
    Write-Host "${White}${Grey} ███████╗   ██║   ███████║██████╔╝███████╗ ${Reset}"
    Write-Host "${White}${Grey} ╚════██║   ██║   ██╔══██║██╔══██╗╚════██║ ${Reset}"
    Write-Host "${White}${Grey} ███████║   ██║   ██║  ██║██║  ██║███████║ ${Reset}"
    Write-Host "${White}${Grey} ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ${Reset}"
    Write-Host ""
    Write-Host "${Gray}   Tools Downloader from Speedyxx  •  v1.0${Reset}"
    Write-Host "${White}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
    Write-Host ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
Show-Banner

$ssFolder   = Get-NextSSFolder
$totalTools = ($Groups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

Write-Host "  ${White}Output folder  ${Gray}$ssFolder${Reset}"
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
Write-Host "  ${White}Files to download: ${Orange}$totalSelected${Reset}"
Write-Host ""
$confirm = (Read-Host "  ${Grey}Proceed? [Y/N]  >${Reset}").Trim().ToUpper()
if ($confirm -ne 'Y') {
    Write-Host ""
    Write-Host "  ${Red}Aborted.${Reset}"
    exit 0
}

# ── Setup output folder + AV exclusion ───────────────────────────────────────
Write-Host ""
Write-Host "  ${White}Creating ${Grey}$ssFolder${Orange}...${Reset}" -NoNewline
$null = New-Item -ItemType Directory -Path $ssFolder -Force
Write-Host " ${Green}✓${Reset}"

Write-Host "  ${White}Adding Windows Defender exclusion...${Reset}" -NoNewline
if (-not (Get-Command -Name 'Add-MpPreference' -ErrorAction SilentlyContinue)) {
    Write-Host " ${Gray}skipped (Defender not present)${Reset}"
} else {
    try {
        Add-MpPreference -ExclusionPath $ssFolder -ErrorAction Stop
        Write-Host " ${Green}✓${Reset}"
    } catch {
        Write-Host " ${Red}✗ (non-fatal — $_)${Reset}"
    }
}

# ── Download ──────────────────────────────────────────────────────────────────
$failed = [System.Collections.Generic.List[string]]::new()

foreach ($groupName in $selectedNames) {
    $urls     = $Groups[$groupName]
    $groupDir = Join-Path $ssFolder $groupName
    $null = New-Item -ItemType Directory -Path $groupDir -Force

    Write-Host ""
    Write-Host "  ${White}━━━ $groupName ${Gray}($($urls.Count) tools)${Reset}"
    Write-Host ""

    foreach ($url in $urls) {
        Invoke-FileDownload -Url $url -GroupFolder $groupDir -FailedList $failed
    }
}

# ── Rename ToolsDownloader++ ───────────────────────────────────────────────────
$toolsDownloader = Get-ChildItem -Path $ssFolder `
    -Recurse `
    -File `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.BaseName -eq 'ToolsDownloader++' -and
        $_.Extension -eq ''
    } |
    Select-Object -First 1

if ($toolsDownloader) {
    $newName = 'ToolsDownloader++.exe'

    try {
        Rename-Item `
            -LiteralPath $toolsDownloader.FullName `
            -NewName $newName `
            -Force `
            -ErrorAction Stop

        Write-Host "  ${Green}✓ Renamed ToolsDownloader++ -> ToolsDownloader++.exe${Reset}"
    }
    catch {
        Write-Host "  ${Red}✗ Failed to rename ToolsDownloader++: $($_.Exception.Message)${Reset}"
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
Write-Host "  ${White}Tools saved to ${Grey}$ssFolder${Reset}"
Write-Host "  ${Grey}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host ""
