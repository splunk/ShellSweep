<img src="src/sweep.png" width="300">

# ShellSweep
*ShellSweeping the evil*

## Why ShellSweep

"ShellSweep" is a PowerShell/Python/Lua tool designed to detect potential webshell files in a specified directory. 

ShellSheep and it's suite of tools calculate the entropy of file contents to estimate the likelihood of a file being a webshell. High entropy indicates more randomness, which is a characteristic of encrypted or obfuscated codes often found in webshells.
- It only processes files with certain extensions (.asp, .aspx, .asph, .php, .jsp), which are commonly used in webshells.
- Certain directories can be excluded from scanning.
- Files with certain hashes can be ignored during the scan.

### How does ShellSweep find the shells?

Entropy, in the context of information theory or data science, is a measure of the unpredictability, randomness, or disorder in a set of data. The concept was introduced by Claude Shannon in his 1948 paper "[A Mathematical Theory of Communication](https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf)".

When applied to a file or a string of text, entropy can help assess the randomness of the data. Here's how it works:
If a file consists of completely random data (each byte is just as likely to be any value between 0 and 255), the entropy is high, close to 8 (since log2(256) = 8).

If a file consists of highly structured data (for example, a text file where most bytes are ASCII characters), the entropy is lower.
In the context of finding webshells or malicious files, entropy can be a useful indicator:
- Many obfuscated scripts or encrypted payloads can have high entropy because the obfuscation or encryption process makes the data look random.
- A normal text file or HTML file would generally have lower entropy because human-readable text has patterns and structure (certain letters are more common, words are usually separated by spaces, etc.).
So, a file with unusually high entropy might be suspicious and worth further investigation. However, it's not a surefire indicator of maliciousness -- there are plenty of legitimate reasons a file might have high entropy, and plenty of ways malware might avoid causing high entropy. It's just one tool in a larger toolbox for detecting potential threats.

ShellSweep includes a Get-Entropy function that calculates the entropy of a file's contents by:
- Counting how often each character appears in the file.
- Using these frequencies to calculate the probability of each character.
- Summing -p*log2(p) for each character, where p is the character's probability. This is the formula for entropy in information theory.

## Feature Comparison

| Feature/Aspect | ShellSweep | ShellSweepPlus |
|----------------|------------|----------------|
| Baseline Detection | Uses hardcoded entropy values for specific file extensions | Dynamic baseline detection that calculates entropy on-the-fly |
| File Extensions | Processes files with extensions: .asp, .aspx, .asax, .jspx, .html, .ashx | Processes files with extensions: .asp, .ashx, .asax, .jspx, .html, .aspx |
| Entropy Calculation | Calculates the entropy of file contents to detect potential webshells | Enhanced entropy-based detection, cross-referencing with suspicious keywords |
| Exclusion Feature | Can exclude certain directories from scanning | Can exclude certain directories from scanning |
| Hash Ignoring | Ignores files with specific hashes | Ignores files with specific hashes |
| Output | If potential webshells are found, outputs file name, entropy value, and hash. Otherwise, prints "No evil identified today." | If potential webshells are found, outputs file name, entropy value, hash, last modified date, detection method, and confidence score in JSON format. Otherwise, prints "No potential webshells detected." |
| Entropy & Standard Deviation | Uses entropy values | Computes the mean and standard deviation of entropy values for each file extension |
| Mixed-Mode Detection | Not present | Uses a combination of entropy-based detection, standard deviation-based detection, and mixed-mode detection (utilizing standard deviation with hardcoded thresholds) |
| Static Code Analysis | Not present | Pattern-based detection mechanism analyzing code statically to identify and flag known malicious patterns |
| Heuristic Analysis | Not present | Introduces `Perform-HeuristicAnalysis` function to detect anomalies based on heuristic rules, enhancing the detection of zero-day webshells |
| Detailed Result Presentation | Not present | Presents potential threats in a structured JSON format, including file path, entropy, standard deviation, hash, last modified date, detection method, and confidence score |
| Comprehensive Logging | Not present | Incorporates `Write-Verbose` commands throughout the script for detailed logging and operational transparency |
| Confidence Scoring | Not present | Calculates a confidence score based on the detection method and adjusts it based on the presence of suspicious patterns |
| Modular Design | Not present | Utilizes separate functions for different tasks (e.g., `Process-File`, `Create-ResultObject`, `Adjust-ConfidenceScore`), promoting code reusability and maintainability |

## ShellScan
ShellScan provides the ability to scan multiple known bad webshell directories and output the average, median, minimum and maximum entropy values by file extension.

Pass ShellScan.ps1 some directories of webshells, any size set. I used:

- https://github.com/tennc/webshell
- https://github.com/BlackArch/webshells
- https://github.com/tarwich/jackal/blob/master/libraries/

This will give a decent training set to get entropy values. 

Output example:

```
Statistics for .aspx files:
Average entropy: 4.94212121048115
Minimum entropy: 1.29348709979974
Maximum entropy: 6.09830238020383
Median entropy: 4.85437969842084
Statistics for .asp files:
Average entropy: 5.51268104400858
Minimum entropy: 0.732406213077191
Maximum entropy: 7.69241278153711
Median entropy: 5.57351177724806

```


## ShellCSV

First, let’s break down the usage of ShellCSV and how it assists with identifying entropy of the good files on disk. The idea is that defenders can run this on web servers to gather all files and entropy values to better understand what paths and extensions are most prominent in their working environment.

See ShellCSV.csv as example output.

## ShellSweep

First, choose your flavor: Python, PowerShell or Lua. 

- Based on results from ShellScan or ShellCSV, modify entropy values as needed.
- Modify file extensions as needed. No need to look for ASPX on a non-ASPX app.
- Modify paths. I don't recommend just scanning all the C:\, lots to filter.
- Modify any filters needed.
- Run it!

If you made it here, this is the part where you iterate on tuning. Find new shell? Gather entropy and modify as needed. 

## ShellSweepPlus

Coming soon!

## Questions
Feel free to open a Git issue.

## Thank You

If you enjoyed this project, be sure to star the project and share with your family and friends. 
