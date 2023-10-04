<#
    Script Name: ShellCSV.ps1
    Author: Michael Haag
    Version: 0.1
    Description:
        "ShellCSV" is a PowerShell tool designed to scan directories for potential webshells and report on their entropy and hash values. Like ShellSweep, it uses entropy as an indicator of potential webshell files.

    How It Works:
        The script calculates the entropy of the contents of each file in the specified directories and with the specified file extensions.
        The entropy, full file path, hash, and date of the scan are stored in a PSObject and added to an array of results.
        After the scan is complete, the results are exported to a CSV file.

    Usage:
        Provide the directory paths to be scanned in the $directoryPaths array.
        Specify the file extensions to be scanned in the $fileExtensions array.
        Run the script in PowerShell.

    Output:
        The script generates a CSV file that contains the full file path, entropy value, file hash, and scan date for each scanned file.
#>



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

# Define the directories and file extensions to scan
#$DirectoryPaths = @(
#    'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\oab',
#    'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth',
#    'C:\inetpub\wwwroot'
#)

$directoryPaths = @('C:\Users\Administrator\Downloads\reGeorg-master\reGeorg-master','C:\Users\Administrator\Downloads\p0wny-shell-master','C:\Users\Administrator\Desktop\10684728197_human2_cisa_report','C:\Users\Administrator\Downloads\xl7dev\WebShell-master','C:\Users\Administrator\Downloads\webshells-master\webshells-master', 'C:\Users\Administrator\Downloads\webshell-master\webshell-master','C:\Users\Administrator\Desktop\10660311902')

$fileExtensions = @('.aspx', '.asp', '.js', '.jsp', '.php','')

# Initialize an array to store the results
$results = @()

# Process each directory and file extension
foreach ($DirectoryPath in $DirectoryPaths) {
    Get-ChildItem $DirectoryPath -Recurse -File | Where-Object { $_.Extension -in $fileExtensions } | foreach {
        $content = Get-Content $_.FullName -Raw
        $entropy = Get-Entropy -String $content
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        $lastModified = $_.LastWriteTime

        # Add the file's details to the results array
        $results += New-Object PSObject -Property @{
            Date = Get-Date -Format "MM/dd/yyyy"
            FullName = $_.FullName
            Entropy = $entropy
            Hash = $hash
            LastModified = $lastModified
        }
    }
}

# Export the results to a CSV file
$results | Export-Csv -Path "c:\temp\shellcsv.csv" -NoTypeInformation