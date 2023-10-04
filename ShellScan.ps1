<#
    Script Name: ShellScan.ps1
    Author: Michael Haag
    Version: 0.1
    Description:
        "ShellScan" is a PowerShell script that calculates and reports entropy statistics for files grouped by extension in specified directories. This script provides an expanded functionality over the previous scripts by including statistical analysis of the entropy values.

    How It Works:
        The script calculates the entropy of the contents of each file in the specified directories. 
        The entropy values are then stored in a hashtable, categorized by file extension.
        After calculating all entropies, the script outputs statistics for each file extension, including the average, minimum, maximum, and median entropy.

    Usage:
        Provide the directory paths to be scanned in the $directoryPaths array.
        Run the script in PowerShell.

    Output:
        The script outputs the entropy statistics for each file extension in the console.
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

# Define the array of directories to scan
$directoryPaths = @('C:\Users\Administrator\Downloads\xl7dev\WebShell-master','C:\Users\Administrator\Downloads\webshells-master\webshells-master', 'C:\Users\Administrator\Downloads\webshell-master\webshell-master','C:\Users\Administrator\Desktop\10660311902')
#$directoryPaths = @('C:\Users\Administrator\Downloads\proxyshell','C:\Users\Administrator\Desktop\10660311902\test')
# Initialize a hashtable to store the entropy values by extension
$entropyValuesByExtension = @{}

# Walk through each directory and calculate the entropy for each file
foreach ($directoryPath in $directoryPaths) {
    Get-ChildItem $directoryPath -Recurse -File | foreach {
        $content = Get-Content $_.FullName -Raw
        $entropy = Get-Entropy -String $content
        $extension = $_.Extension
        $lastModified = $_.LastWriteTime
        if (-not $entropyValuesByExtension.ContainsKey($extension)) {
            $entropyValuesByExtension[$extension] = @()
        }
        $entropyValuesByExtension[$extension] += $entropy
        Write-Output "$($_.FullName) - Last Modified: ${lastModified}: Entropy: $entropy"
    }
}

# Calculate and output the entropy statistics for each file extension
foreach ($extension in $entropyValuesByExtension.Keys) {
    $entropyValues = $entropyValuesByExtension[$extension]
    $entropyStats = $entropyValues | Measure-Object -Average -Minimum -Maximum
    Write-Output "Statistics for $extension files:"
    Write-Output "Average entropy: $($entropyStats.Average)"
    Write-Output "Minimum entropy: $($entropyStats.Minimum)"
    Write-Output "Maximum entropy: $($entropyStats.Maximum)"

    # To calculate the median, we need to sort the values and find the middle one
    $sortedEntropyValues = $entropyValues | Sort-Object
    $middleIndex = $sortedEntropyValues.Count / 2
    if ($sortedEntropyValues.Count % 2 -eq 0) {
        # If there is an even number of values, the median is the average of the two middle values
        $medianEntropy = ($sortedEntropyValues[$middleIndex-1] + $sortedEntropyValues[$middleIndex]) / 2
    } else {
        # If there is an odd number of values, the median is the middle value
        $medianEntropy = $sortedEntropyValues[[Math]::Floor($middleIndex)]
    }
    Write-Output "Median entropy: $medianEntropy"
}