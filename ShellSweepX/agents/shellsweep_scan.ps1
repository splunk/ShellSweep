<#
.SYNOPSIS
ShellSweep Scan - Scans directories for potential webshells and reports findings to a central server.

.DESCRIPTION
This PowerShell script is part of the ShellSweep system. It scans specified directories for files, optionally filtering by extensions, and sends the file information and content to a central server for analysis. This script is designed to be run as an agent in the ShellSweep ecosystem.

.PARAMETER server
The URL of the ShellSweep server to send the scan results to.

.PARAMETER scanDirectory
The directory to scan for potential webshells.

.PARAMETER extensions
Optional. A comma-separated list of file extensions to scan. If not provided, all files will be scanned.

.EXAMPLE
.\shellsweep_scan.ps1 -server "http://shellsweep-server:8080" -scanDirectory "C:\inetpub\wwwroot"

.EXAMPLE
.\shellsweep_scan.ps1 -server "http://shellsweep-server:8080" -scanDirectory "D:\web" -extensions ".php,.asp,.aspx"

.NOTES
Author: Michael Haag
Version: 1.2
Requires: PowerShell 5.1 or later

.LINK
https://github.com/splunk/ShellSweep
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$server,
    
    [Parameter(Mandatory=$true)]
    [string]$scanDirectory,
    
    [Parameter(Mandatory=$false)]
    [string]$extensions
)

function Send-File {
    param (
        [string]$filePath,
        [int]$maxFileSizeMB = 10 
    )
    
    $fileInfo = Get-Item $filePath
    $fileSize = $fileInfo.Length
    $fileSizeMB = $fileSize / 1MB

    if ($fileSizeMB -gt $maxFileSizeMB) {
        Write-Host "Skipping file (too large): $filePath ($fileSizeMB MB)"
        return
    }

    $lastModified = $fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $fileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
    $base64Content = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($filePath))

    $payload = @{
        agent_id = $env:COMPUTERNAME
        computer_name = $env:COMPUTERNAME
        results = @(
            @{
                FilePath = $filePath
                Hash = $fileHash
                LastModified = $lastModified
                FileSize = $fileSize
                Content = $base64Content
            }
        )
    }

    $jsonPayload = ConvertTo-Json -InputObject $payload -Depth 3 -Compress

    try {
        Invoke-RestMethod -Uri "$server/api/agent_results" -Method Post -Body $jsonPayload -ContentType "application/json"
        Write-Host "File sent successfully: $filePath"
    }
    catch {
        Write-Host "Failed to send file: $filePath. Error: $_"
    }
}

$batchSize = 50
$waitTime = 20
$processedFiles = 0

function Process-Files {
    param (
        [string]$path,
        [string[]]$fileExtensions,
        [int]$maxFileSizeMB = 10
    )

    $files = if ($fileExtensions) {
        Get-ChildItem -Path $path -File -Recurse -Include $fileExtensions
    } else {
        Get-ChildItem -Path $path -File -Recurse
    }

    $totalFiles = $files.Count
    Write-Host "Total files to process: $totalFiles"

    $script:processedFiles = 0

    foreach ($file in $files) {
        Send-File -filePath $file.FullName -maxFileSizeMB $maxFileSizeMB
        $script:processedFiles++

        if ($script:processedFiles % $batchSize -eq 0) {
            Write-Host "Progress: $script:processedFiles / $totalFiles files processed"
            Write-Host "Waiting for $waitTime seconds before processing next batch..."
            Start-Sleep -Seconds $waitTime
        }
    }
}

$maxFileSizeMB = 10

if ([string]::IsNullOrEmpty($extensions)) {
    Process-Files -path $scanDirectory -maxFileSizeMB $maxFileSizeMB
}
else {
    $extArray = $extensions -split ',' | ForEach-Object { "*$_" }
    Process-Files -path $scanDirectory -fileExtensions $extArray -maxFileSizeMB $maxFileSizeMB
}

Write-Host "Scan completed. Total files processed: $processedFiles"