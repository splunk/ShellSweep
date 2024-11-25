<#
.SYNOPSIS
ShellSweep Agent - Scans directories for potential webshells and reports findings to a central server.

.DESCRIPTION
This PowerShell script acts as an agent for the ShellSweep system. It scans specified directories for files that may be potential webshells, using entropy analysis and other heuristics. The script retrieves its configuration from a central server, performs the scan, and reports any findings back to the server.

To setup a scheduled task to run the agent daily at 3AM:
schtasks /create /tn "ShellSweepX Daily Scan" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Path\To\shellsweep_agent.ps1 -ServerUrl 'http://shellsweep-server:8080'" /sc daily /st 03:00


.PARAMETER ServerUrl
The URL of the ShellSweep server to connect to for configuration and reporting.

.EXAMPLE
.\shellsweep_agent.ps1 -ServerUrl "http://shellsweep-server:8080"

.NOTES
Author: Michael Haag
Version: 1.1
Requires: PowerShell 5.1 or later
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl
)

# Constants
$MAX_FILE_SIZE_MB = 10
$BATCH_SIZE = 50
$WAIT_TIME = 20

function Get-ConfigurationFile {
    param ([string]$ServerUrl)
    try {
        $configUrl = "$ServerUrl/api/agent_config"
        $config = Invoke-RestMethod -Uri $configUrl -Method Get
        return $config
    }
    catch {
        Write-Error "Failed to retrieve configuration: $_"
        return $null
    }
}

function Get-Entropy {
    param ([byte[]]$Bytes)
    $freqTable = @{}
    $Bytes | ForEach-Object { $freqTable[$_]++ }
    $entropy = 0
    $Bytes.Length | ForEach-Object {
        $freq = $freqTable[$_] / $Bytes.Length
        $entropy -= $freq * [Math]::Log($freq, 2)
    }
    return $entropy
}

function Test-FileEntropy {
    param (
        $File,
        $FileExtensions
    )
    $chunkSize = 1MB
    $totalEntropy = 0
    $chunkCount = 0
    $maxEntropy = 0

    try {
        $stream = [System.IO.File]::OpenRead($File.FullName)
        $buffer = New-Object byte[] $chunkSize
        while ($bytesRead = $stream.Read($buffer, 0, $chunkSize)) {
            $chunkEntropy = Get-Entropy -Bytes $buffer[0..($bytesRead-1)]
            if (-not [double]::IsNaN($chunkEntropy)) {
                $totalEntropy += $chunkEntropy
                $chunkCount++
                $maxEntropy = [Math]::Max($maxEntropy, $chunkEntropy)
            }
        }
    }
    finally {
        if ($stream) { $stream.Close() }
    }

    $averageEntropy = if ($chunkCount -gt 0) { $totalEntropy / $chunkCount } else { 0 }
    $conditions = $FileExtensions[$File.Extension]
    foreach ($condition in $conditions) {
        $operation = $condition.operation
        $value = $condition.value
        switch ($operation) {
            'gt' { if ($maxEntropy -gt $value -or $averageEntropy -gt $value) { return $true } }
            'lt' { if ($maxEntropy -lt $value -and $averageEntropy -lt $value) { return $true } }
            'eq' { if ($maxEntropy -eq $value -or $averageEntropy -eq $value) { return $true } }
        }
    }
    return $false
}

function Get-LastScanTime {
    $lastScanFile = "$env:TEMP\shellsweep_last_scan.txt"
    if (Test-Path $lastScanFile) {
        return [DateTime]::Parse((Get-Content $lastScanFile))
    } else {
        return $null
    }
}

function Set-LastScanTime {
    $lastScanFile = "$env:TEMP\shellsweep_last_scan.txt"
    (Get-Date).ToString("o") | Set-Content $lastScanFile
}

function Scan-Directories {
    param (
        $Config,
        [Parameter(Mandatory=$false)]
        [Nullable[DateTime]]$LastScanTime,
        [string]$ServerUrl
    )
    $totalFiles = 0
    $sentFiles = 0
    $failedFiles = 0

    foreach ($dir in $Config.directory_paths) {
        if ($dir -match "^/") {
            Write-Verbose "Skipping Linux-style path: $dir"
            continue
        }
        if (Test-Path $dir) {
            Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                $totalFiles++
                if ($_.Extension -in $Config.file_extensions.Keys -and
                    ($null -eq $LastScanTime -or $_.LastWriteTime -gt $LastScanTime) -and
                    ($_.Length / 1MB) -le $MAX_FILE_SIZE_MB) {
                    if (Test-FileEntropy -File $_ -FileExtensions $Config.file_extensions) {
                        $fileInfo = @{
                            FilePath = $_.FullName
                            Hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
                            LastModified = $_.LastWriteTimeUtc.ToString("o")
                            FileSize = $_.Length
                        }
                        $sendResult = Send-SingleResult -Result $fileInfo -ServerUrl $ServerUrl
                        if ($sendResult) {
                            $sentFiles++
                        } else {
                            $failedFiles++
                        }
                    }
                }
            }
        } else {
            Write-Verbose "Directory not found: $dir"
        }
    }
    return @{
        TotalFiles = $totalFiles
        SentFiles = $sentFiles
        FailedFiles = $failedFiles
    }
}

function Send-SingleResult {
    param ($Result, [string]$ServerUrl)
    try {
        $fileContent = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Result.FilePath))
        $payload = @{
            agent_id = (Get-AgentId).ToString().Trim()
            computer_name = $env:COMPUTERNAME
            results = @(@{
                FilePath = $Result.FilePath
                Hash = $Result.Hash
                LastModified = $Result.LastModified
                FileSize = $Result.FileSize
                Content = $fileContent
            })
        }
        $jsonPayload = ConvertTo-Json -InputObject $payload -Depth 3 -Compress
        Invoke-RestMethod -Uri "$ServerUrl/api/agent_results" -Method Post -Body $jsonPayload -ContentType "application/json"
        Write-Verbose "File sent successfully: $($Result.FilePath)"
        return $true
    }
    catch {
        Write-Warning "Failed to send file: $($Result.FilePath). Error: $_"
        return $false
    }
}

function Send-Results {
    param ($Results, [string]$ServerUrl)
    try {
        $totalFiles = $Results.Count
        $successfulUploads = 0
        $failedUploads = 0

        for ($i = 0; $i -lt $Results.Count; $i += $BATCH_SIZE) {
            $batch = $Results[$i..([Math]::Min($i + $BATCH_SIZE - 1, $Results.Count - 1))]
            $payload = @{
                agent_id = (Get-AgentId).ToString().Trim()
                computer_name = $env:COMPUTERNAME
                results = @()
            }

            foreach ($result in $batch) {
                try {
                    $fileContent = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($result.FilePath))
                    $payload.results += @{
                        FilePath = $result.FilePath
                        Hash = $result.Hash
                        LastModified = $result.LastModified
                        FileSize = $result.FileSize
                        Content = $fileContent
                    }
                    $successfulUploads++
                }
                catch {
                    Write-Warning "Failed to process file: $($result.FilePath). Error: $_"
                    $failedUploads++
                }
            }

            $jsonPayload = ConvertTo-Json -InputObject $payload -Depth 3 -Compress
            Invoke-RestMethod -Uri "$ServerUrl/api/agent_results" -Method Post -Body $jsonPayload -ContentType "application/json"
            
            Write-Verbose "Sent batch of $($batch.Count) files. Total progress: $successfulUploads/$totalFiles"

            if ($i + $BATCH_SIZE -lt $Results.Count) {
                Write-Verbose "Waiting for $WAIT_TIME seconds before sending next batch..."
                Start-Sleep -Seconds $WAIT_TIME
            }
        }

        Write-Output "Upload summary: $successfulUploads/$totalFiles files sent successfully, $failedUploads failed."
        return @{
            SuccessfulUploads = $successfulUploads
            FailedUploads = $failedUploads
            TotalFiles = $totalFiles
        }
    }
    catch {
        Write-Error "Failed to process results. Error: $_"
        return $null
    }
}

function Send-AgentCheckin {
    param ([string]$ServerUrl)
    try {
        $agentId = Get-AgentId
        $body = @{
            agent_id = $agentId.ToString().Trim()
            computer_name = $env:COMPUTERNAME
        } | ConvertTo-Json

        $headers = @{"Content-Type" = "application/json"}
        Write-Verbose "Sending payload: $body"
        $response = Invoke-RestMethod -Uri "$ServerUrl/api/agent_checkin" -Method Post -Body $body -Headers $headers
        return $response
    }
    catch {
        Write-Error "Failed to send agent check-in: $_"
        return $null
    }
}

function Get-AgentId {
    $agentIdFile = "$env:TEMP\shellsweep_agent_id.txt"
    if (Test-Path $agentIdFile) {
        return (Get-Content $agentIdFile).Trim()
    } else {
        $newAgentId = [guid]::NewGuid().ToString()
        $newAgentId | Set-Content $agentIdFile
        return $newAgentId
    }
}

# Main execution
$configPath = "$env:TEMP\shellsweep_config.yaml"
$config = Get-ConfigurationFile -ServerUrl $ServerUrl
if ($config) {
    $config | ConvertTo-Yaml | Set-Content $configPath
    $yamlConfig = Get-Content $configPath -Raw | ConvertFrom-Yaml
    Write-Verbose "Configuration loaded successfully"
    
    $checkinResult = Send-AgentCheckin -ServerUrl $ServerUrl
    Write-Verbose "Agent check-in result: $($checkinResult | Out-String)"
    
    $lastScanTime = Get-LastScanTime
    $scanMessage = if ($lastScanTime) { "Performing subsequent scan for files modified after $($lastScanTime.ToString('o'))" } else { "Performing initial scan of all files" }
    Write-Verbose $scanMessage
    
    Write-Verbose "Starting directory scan..."
    $scanResult = Scan-Directories -Config $yamlConfig -LastScanTime $lastScanTime -ServerUrl $ServerUrl
    Write-Verbose "Scan completed. Total files: $($scanResult.TotalFiles), Sent: $($scanResult.SentFiles), Failed: $($scanResult.FailedFiles)"
    
    if ($scanResult.SentFiles -gt 0 -or $scanResult.FailedFiles -gt 0) {
        Write-Verbose "Results summary: $($scanResult.SentFiles) files sent successfully, $($scanResult.FailedFiles) failed."
    } else {
        Write-Verbose "No issues found. No files were sent."
    }
    
    Set-LastScanTime
} else {
    Write-Warning "Failed to retrieve configuration. Using last known good configuration."
    if (Test-Path $configPath) {
        $yamlConfig = Get-Content $configPath -Raw | ConvertFrom-Yaml
        Write-Verbose "Starting directory scan with last known configuration..."
        $results = Scan-Directories -Config $yamlConfig
        Write-Verbose "Scan completed. Found $($results.Count) potential issues."
        
        if ($results.Count -gt 0) {
            Write-Verbose "Attempting to send results to server..."
            $sendResult = Send-Results -Results $results -ServerUrl $ServerUrl
            if ($null -eq $sendResult) {
                Write-Error "Failed to send results to server."
            } else {
                Write-Verbose "Results sent to server. Summary: $($sendResult.SuccessfulUploads)/$($sendResult.TotalFiles) files sent successfully, $($sendResult.FailedUploads) failed."
            }
        } else {
            Write-Verbose "No issues found. Skipping result submission."
        }
    } else {
        Write-Error "No configuration available. Exiting."
        exit 1
    }
}