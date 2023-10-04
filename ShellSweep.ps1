<#
    Script Name: ShellSweep.ps1
    Author: Michael Haag
    Version: 0.1
    Description:
        "ShellSweep" is a PowerShell tool designed to detect potential webshell files in a specified directory. 
        A webshell is a script that can be uploaded to a web server to enable remote administration of the machine. They are often used in malicious activities such as server infiltration and data extraction.

    How It Works:
        The script calculates the entropy of file contents to estimate the likelihood of a file being a webshell. High entropy indicates more randomness, which is a characteristic of encrypted or obfuscated codes often found in webshells.
        It only processes files with certain extensions (.asp, .aspx, .asph, .php, .jsp), which are commonly used in webshells.
        Certain directories can be excluded from scanning.
        Files with certain hashes can be ignored during the scan.

    Usage:
        Provide the directory paths to be scanned in the $DirectoryPaths array.
        Specify the directories to be excluded from the scan in the $excludePaths array.
        Specify the file hashes to be ignored during the scan in the $ignoreHashes array or a text file specified in $ignoreHashesFilePath.
        Run the script in PowerShell.

    Output:
        If potential webshells are found, the script prints out the file name, its entropy value, and its hash.
        If no webshells are found, the script prints "No evil identified today."
#>


Write-Output @"
  ██████  ██░ ██ ▓█████  ██▓     ██▓      ██████  █     █░▓█████ ▓█████  ██▓███  
▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    ▒██    ▒ ▓█░ █ ░█░▓█   ▀ ▓█   ▀ ▓██░  ██▒
░ ▓██▄   ▒██▀▀██░▒███   ▒██░    ▒██░    ░ ▓██▄   ▒█░ █ ░█ ▒███   ▒███   ▓██░ ██▓▒
  ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░      ▒   ██▒░█░ █ ░█ ▒▓█  ▄ ▒▓█  ▄ ▒██▄█▓▒ ▒
▒██████▒▒░▓█▒░██▓░▒████▒░██████▒░██████▒▒██████▒▒░░██▒██▓ ░▒████▒░▒████▒▒██▒ ░  ░
▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░ ▓░▒ ▒  ░░ ▒░ ░░░ ▒░ ░▒▓▒░ ░  ░
░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░  ▒ ░ ░   ░ ░  ░ ░ ░  ░░▒ ░     
░  ░  ░   ░  ░░ ░   ░     ░ ░     ░ ░   ░  ░  ░    ░   ░     ░      ░   ░░       
      ░   ░  ░  ░   ░  ░    ░  ░    ░  ░      ░      ░       ░  ░   ░  ░         
                                                                                 
"@


# Entropy thresholds and operations for each file extension using nested array of hashtables, each containing an 'operation' and a 'value'.
# We recommend only going after the file extensions most found in your environment (asp* for IIS/Exchange). Use ShellCSV to identify what is in the paths to be monitored.

$fileExtensions = @{
    '.asp' = @(
        @{ 'operation' = 'lt'; 'value' = 0.805376867704514 },
        @{ 'operation' = 'gt'; 'value' =  5.51268104400858 }
    )
    '.ashx' = @(@{ 'operation' = 'gt'; 'value' =  3.75840459657413 })
    '.asax' = @(@{ 'operation' = 'gt'; 'value' = 3.7288741494524 })
    '.jspx' = @(@{ 'operation' = 'gt'; 'value' = 4.87651397975203 })
    '.html' = @(@{ 'operation' = 'gt'; 'value' = 4.8738392644771 })
    '.aspx' = @(
        @{ 'operation' = 'lt'; 'value' = 0.805376867704514 },
        @{ 'operation' = 'gt'; 'value' =  4.15186444439319 }
    )
    '.php' = @(@{ 'operation' = 'gt'; 'value' =  4.23015141285636 })
    '.jsp' = @(@{ 'operation' = 'gt'; 'value' =   4.40958415652662 })
    '.js' = @(@{ 'operation' = 'gt'; 'value' =  4.25868439013462 })
}


# Calculate the entropy of a given string
function Get-Entropy {
    param(
        [Parameter(Mandatory=$true, Position=0)] [string] $String
    )

    $length = $String.Length
    $symbolFrequency = @{}
    foreach ($symbol in $String.ToCharArray()) {
        if ($symbolFrequency.ContainsKey($symbol)) {
            $symbolFrequency[$symbol]++
        } else {
            $symbolFrequency.Add($symbol, 1)
        }
    }

    $entropy = 0
    $symbolFrequency.Values | foreach {
        $freq = $_ / $length
        $entropy -= $freq * [Math]::Log($freq, 2)
    }

    return $entropy
}

# Directories to scan
$DirectoryPaths =  @('C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\oab','C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\','C:\inetpub\wwwroot') 

# Directories to exclude
$excludePaths = @('C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\15.1.1713\scripts','C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\Current\scripts\premium','C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\Current\scripts\','C:\Windows\WinSxS','C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\Owa\Current2\version\debug\scripts\','C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess\ecp\Current\scripts\')

# File hashes to ignore. If the list is too long, use the txt file next.
$ignoreHashes = @('FE3F0B4326FF9754CB8B61AA3CEFB465A5308658064EE51C41B0A8B50027728D','B6675117A7B174C3AA2510DDDEFF4221BA6E31005333F47C7239ED5D055BBBDD', '54EFA324203B762A03033879057F8A9DB0F7B45C83C8E1A40529CAFF1EB18004','71FE41C6CCB0023576483A1C89929255480A4F5F0F07CFF9A8D2030ECF70E7AE')

# Path to a txt file containing hashes to ignore
$ignoreHashesFilePath = 'path_to_your_file.txt'

# Read the hashes from the file into an array
$fileHashes = Get-Content $ignoreHashesFilePath

if ($fileHashes) {
    $ignoreHashes = $fileHashes
}

$webshellFound = $false

# Walk through each directory and flag files with high/low entropy
foreach ($DirectoryPath in $DirectoryPaths) {
    Get-ChildItem $DirectoryPath -Recurse -File | foreach {
        $exclude = $false
        foreach($excludePath in $excludePaths) {
            if ($_.DirectoryName.StartsWith($excludePath)) {
                $exclude = $true
                break
            }
        }

        if ($_.Extension -in $fileExtensions.Keys -and -not $exclude) {
            $content = Get-Content $_.FullName -Raw
            $entropy = Get-Entropy -String $content
            $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash

            foreach ($condition in $fileExtensions[$_.Extension]) {
                $operation = $condition['operation']
                $value = $condition['value']
                $metCondition = $false
                switch ($operation) {
                    'gt' { if ($entropy -gt $value) { $metCondition = $true } }
                    'lt' { if ($entropy -lt $value) { $metCondition = $true } }
                    'eq' { if ($entropy -eq $value) { $metCondition = $true } }
                }

                if ($metCondition -and $hash -notin $ignoreHashes) {
                    $lastModified = $_.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    # Create a new object and add it to the results array
                    $result = New-Object PSObject -Property @{
                        'FilePath' = $_.FullName
                        'Entropy' = $entropy
                        'Hash' = $hash
                        'LastModified' = $lastModified
                    }
                    # Convert the result to JSON and output to stdout
                    $result | ConvertTo-Json -Compress
                    $webshellFound = $true
                }
            }
        }
    }
}
# If no webshells were found -->
if (-not $webshellFound) {
    # Create a special result
    $result = New-Object PSObject -Property @{
        'Message' = "No evil identified today."
    }
    # Convert the result to JSON and output to stdout
    $result | ConvertTo-Json -Compress
}