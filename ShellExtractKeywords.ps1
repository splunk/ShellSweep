# This script is used to extract keywords from a set of directories containing webshell files.
# It reads each file, splits the content into words and updates each word's frequency in a hash table.
# It then filters out words that appear more than 3 times and considers them as suspicious.
# The suspicious words are then written to a file 'suspiciousPatterns.txt'.


 $webshellDirectoryPath = @(
    'C:\Users\Administrator\Downloads\reGeorg-master\reGeorg-master',
    'C:\Users\Administrator\Downloads\p0wny-shell-master',
    'C:\Users\Administrator\Desktop\10684728197_human2_cisa_report',
    'C:\Users\Administrator\Downloads\xl7dev\WebShell-master',
    'C:\Users\Administrator\Downloads\webshells-master\webshells-master',
    'C:\Users\Administrator\Downloads\webshell-master\webshell-master',
    'C:\Users\Administrator\Desktop\10660311902'
)

$wordFrequencyInDirectory = @{}

# Walk through each file in the directory
Get-ChildItem $webshellDirectoryPath -File | foreach {
    $content = Get-Content $_.FullName -Raw

    # Split the content into words and update each word's frequency in the hash table
    $content -split '\s+' | foreach {
        if ($wordFrequencyInDirectory.ContainsKey($_)) {
            $wordFrequencyInDirectory[$_]++
        } else {
            $wordFrequencyInDirectory.Add($_, 1)
        }
    }
}

# Filter out words that appear more than 3 times
$suspiciousWords = $wordFrequencyInDirectory.GetEnumerator() | Where-Object { $_.Value -gt 3 } | ForEach-Object { $_.Key }

$output = "`$suspiciousPatterns = @(" + "`r`n"
foreach ($word in $suspiciousWords) {
    $output += "    '$word'," + "`r`n"
}
$output += ")"

$output | Out-File -FilePath 'C:\temp\suspiciousPatterns.txt'
 
