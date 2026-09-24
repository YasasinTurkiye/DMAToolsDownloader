[CmdletBinding()]
param()

# ─────────────────────────────────────────────────────────────────────────────
# Administrator check
# ─────────────────────────────────────────────────────────────────────────────

if (-not (
    [Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please re-run from an elevated PowerShell session." -ForegroundColor Yellow
    exit 1
}

$ProgressPreference = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────────────────────
# Network setup
# ─────────────────────────────────────────────────────────────────────────────

Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

try {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12
} catch {}

[System.Net.ServicePointManager]::DefaultConnectionLimit = 64
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::UseNagleAlgorithm = $false

# ─────────────────────────────────────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────────────────────────────────────

$e = [char]27

$White = "${e}[38;2;245;245;245m"
$Grey  = "${e}[38;2;190;190;190m"
$Gray  = "${e}[38;2;125;125;125m"
$Green = "${e}[38;2;80;220;80m"
$Red   = "${e}[91m"
$Reset = "${e}[0m"

# ─────────────────────────────────────────────────────────────────────────────
# Tool groups
# ─────────────────────────────────────────────────────────────────────────────
$Groups = [ordered]@{
    "DMA Forensics" = @(
       'https://raw.githubusercontent.com/YasasinTurkiye/1./main/Aim%20Device%20Scanner.exe'
       'https://raw.githubusercontent.com/YasasinTurkiye/1./main/DMA-multitool.exe'
       'https://raw.githubusercontent.com/YasasinTurkiye/1./main/Hash%26History%20Scanner.exe'
       'https://raw.githubusercontent.com/YasasinTurkiye/1./main/RAM%20DUMP%20Analyzer.exe'
       'https://raw.githubusercontent.com/YasasinTurkiye/1./main/Setup.Api.Dev%20Analyzer.exe'
       'https://raw.githubusercontent.com/YasasinTurkiye/1./main/TLP%20Contactor.exe'
    )
}

# ─────────────────────────────────────────────────────────────────────────────
# Output folder
# ─────────────────────────────────────────────────────────────────────────────

$OutputFolder = "C:\DMA Forensics"

# ─────────────────────────────────────────────────────────────────────────────
# HTTP client
# ─────────────────────────────────────────────────────────────────────────────

$HttpHandler = [System.Net.Http.HttpClientHandler]::new()

try {
    $HttpHandler.AutomaticDecompression =
        [System.Net.DecompressionMethods]"GZip, Deflate"
} catch {
    $HttpHandler.AutomaticDecompression =
        [System.Net.DecompressionMethods]::GZip
}

$HttpClient = [System.Net.Http.HttpClient]::new($HttpHandler)

$HttpClient.Timeout = [TimeSpan]::FromMinutes(10)

$HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd(
    "DMA-Forensics-Downloader/1.0"
)

$HttpClient.DefaultRequestHeaders.ConnectionClose = $false

$BufferSize = 262144

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

function Show-Banner {
    Clear-Host

    Write-Host ""
    Write-Host "${White} ███████╗████████╗ █████╗ ██████╗ ███████╗${Reset}"
    Write-Host "${White} ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝${Reset}"
    Write-Host "${White} ███████╗   ██║   ███████║██████╔╝███████╗${Reset}"
    Write-Host "${White} ╚════██║   ██║   ██╔══██║██╔══██╗╚════██║${Reset}"
    Write-Host "${White} ███████║   ██║   ██║  ██║██║  ██║███████║${Reset}"
    Write-Host "${White} ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝${Reset}"
    Write-Host ""
    Write-Host "${Gray}   DMA Forensics${Reset}"
    Write-Host "${White}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Filename helper
# ─────────────────────────────────────────────────────────────────────────────

function Get-FilenameFromUrl {
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    try {
        $uri = [System.Uri]$Url
        $name = [System.IO.Path]::GetFileName(
            [System.Uri]::UnescapeDataString($uri.AbsolutePath)
        )

        if ([string]::IsNullOrWhiteSpace($name)) {
            return $null
        }

        return $name
    }
    catch {
        return $null
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Download function
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-FileDownload {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$DestinationFolder,

        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$FailedList
    )

    $response = $null
    $fileStream = $null
    $netStream = $null
    $destination = $null

    $filename = Get-FilenameFromUrl -Url $Url

    if ([string]::IsNullOrWhiteSpace($filename)) {
        Write-Host "    ${Red}✗ Invalid filename${Reset}"
        $FailedList.Add($Url)
        return
    }

    Write-Host "    ${Grey}↓ $filename${Reset} " -NoNewline

    try {
        $response = $HttpClient.GetAsync(
            $Url,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()

        if (-not $response.IsSuccessStatusCode) {
            throw "HTTP $([int]$response.StatusCode) $($response.ReasonPhrase)"
        }

        $destination = Join-Path $DestinationFolder $filename

        # Don't overwrite existing files
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($filename)
        $extension = [System.IO.Path]::GetExtension($filename)

        $n = 2

        while (Test-Path -LiteralPath $destination) {
            $destination = Join-Path `
                $DestinationFolder `
                ("{0}_{1}{2}" -f $baseName, $n, $extension)

            $n++
        }

        $fileStream = [System.IO.FileStream]::new(
            $destination,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            $BufferSize,
            [System.IO.FileOptions]::SequentialScan
        )

        $netStream = $response.Content.ReadAsStreamAsync().
            GetAwaiter().
            GetResult()

        $netStream.CopyTo($fileStream, $BufferSize)

        $fileStream.Flush()

        Write-Host "${Green}✓${Reset}"
    }
    catch {
        Write-Host "${Red}✗${Reset}"
        Write-Host "      ${Gray}$($_.Exception.Message)${Reset}"

        $FailedList.Add($Url)

        if ($destination -and (Test-Path -LiteralPath $destination)) {
            Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        if ($netStream) {
            $netStream.Dispose()
        }

        if ($fileStream) {
            $fileStream.Dispose()
        }

        if ($response) {
            $response.Dispose()
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

Show-Banner

$totalTools = (
    $Groups.Values |
    ForEach-Object { $_.Count } |
    Measure-Object -Sum
).Sum

Write-Host "  ${White}Output folder  ${Gray}$OutputFolder${Reset}"
Write-Host "  ${Gray}Total tools    ${White}$totalTools${Reset}"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Download mode
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "  ${White}Download mode:${Reset}"
Write-Host ""
Write-Host "    ${Grey}[A]${Reset}  All tools ${Gray}($totalTools files)${Reset}"
Write-Host "    ${Grey}[C]${Reset}  Choose specific groups"
Write-Host ""

$mode = (Read-Host "  >").Trim().ToUpper()

[string[]]$selectedNames = @()

if ($mode -eq "A") {

    $selectedNames = @($Groups.Keys)

}
elseif ($mode -eq "C") {

    Write-Host ""
    Write-Host "  ${White}Available groups:${Reset}"
    Write-Host ""

    $groupKeys = @($Groups.Keys)

    for ($i = 0; $i -lt $groupKeys.Count; $i++) {

        $count = $Groups[$groupKeys[$i]].Count

        Write-Host "    ${Gray}[$($i + 1)]${Reset} $($groupKeys[$i]) ${Gray}($count tools)${Reset}"
    }

    Write-Host ""
    Write-Host "  ${White}Enter group numbers separated by commas${Reset}"
    Write-Host "  ${Gray}Example: 1,3,5${Reset}"
    Write-Host ""

    $raw = (Read-Host "  >").Trim()

    foreach ($part in ($raw -split ",")) {

        $part = $part.Trim()

        if ($part -match "^\d+$") {

            $index = [int]$part - 1

            if ($index -ge 0 -and $index -lt $groupKeys.Count) {
                $selectedNames += $groupKeys[$index]
            }
        }
    }

    $selectedNames = @($selectedNames | Select-Object -Unique)

    if ($selectedNames.Count -eq 0) {
        Write-Host ""
        Write-Host "  ${Red}No valid groups selected. Exiting.${Reset}"
        exit 0
    }

}
else {

    Write-Host ""
    Write-Host "  ${Red}Invalid choice. Exiting.${Reset}"
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Confirmation
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ${White}Selected groups:${Reset}"
Write-Host ""

$totalSelected = 0

foreach ($name in $selectedNames) {

    $count = $Groups[$name].Count
    $totalSelected += $count

    Write-Host "    ${Grey}• $name ${Gray}($count tools)${Reset}"
}

Write-Host ""
Write-Host "  ${White}Files to download: ${Grey}$totalSelected${Reset}"
Write-Host ""

$confirm = (
    Read-Host "  ${Gray}Proceed? [Y/N]${Reset}"
).Trim().ToUpper()

if ($confirm -ne "Y") {

    Write-Host ""
    Write-Host "  ${Red}Aborted.${Reset}"
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Create output folder
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ${White}Creating ${Gray}$OutputFolder${Reset}..." -NoNewline

try {
    $null = New-Item `
        -ItemType Directory `
        -Path $OutputFolder `
        -Force `
        -ErrorAction Stop

    Write-Host " ${Green}✓${Reset}"
}
catch {

    Write-Host " ${Red}✗${Reset}"
    Write-Host ""
    Write-Host "  ${Red}$($_.Exception.Message)${Reset}"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Download
# ─────────────────────────────────────────────────────────────────────────────

$failed = [System.Collections.Generic.List[string]]::new()

foreach ($groupName in $selectedNames) {

    $urls = $Groups[$groupName]

    # Files go directly into C:\DMA Forensics
    $groupDir = $OutputFolder

    Write-Host ""
    Write-Host "  ${White}━━━ $groupName ${Gray}($($urls.Count) tools)${Reset}"
    Write-Host ""

    foreach ($url in $urls) {

        Invoke-FileDownload `
            -Url $url `
            -DestinationFolder $groupDir `
            -FailedList $failed
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

$succeeded = $totalSelected - $failed.Count

Write-Host ""
Write-Host "  ${White}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host "  ${Green}✓ Downloaded : $succeeded / $totalSelected${Reset}"

if ($failed.Count -gt 0) {

    Write-Host "  ${Red}✗ Failed     : $($failed.Count)${Reset}"
    Write-Host ""
    Write-Host "  ${Red}Failed URLs:${Reset}"

    foreach ($url in $failed) {
        Write-Host "    ${Gray}$url${Reset}"
    }
}

Write-Host ""
Write-Host "  ${White}Tools saved to ${Gray}$OutputFolder${Reset}"
Write-Host "  ${White}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Reset}"
Write-Host ""