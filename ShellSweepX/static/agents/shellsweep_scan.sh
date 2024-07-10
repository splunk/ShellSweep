#!/bin/bash

# ShellSweep Scan - Scans directories for potential webshells and reports findings to a central server.
#
# Description:
# This Bash script is part of the ShellSweep system. It scans specified directories for files,
# optionally filtering by extensions, and sends the file information and content to a central server
# for analysis. This script is designed to be run as an agent in the ShellSweep ecosystem.
#
# Usage:
#   ./shellsweep_scan.sh -server <server_url> -directory <scan_directory> [-extensions <file_extensions>]
#
# Parameters:
#   -server       The URL of the ShellSweep server to send the scan results to.
#   -directory    The directory to scan for potential webshells.
#   -extensions   Optional. A comma-separated list of file extensions to scan. If not provided, all files will be scanned.
#
# Examples:
#   ./shellsweep_scan.sh -server "http://shellsweep-server:8080" -directory "/var/www/html"
#   This example scans the /var/www/html directory and sends all file information to the specified server.
#
#   ./shellsweep_scan.sh -server "http://shellsweep-server:8080" -directory "/var/www" -extensions "php,asp,aspx"
#   This example scans the /var/www directory, only processing files with .php, .asp, or .aspx extensions,
#   and sends the results to the specified server.
#
# Author: Michael Haag
# Version: 1.0
# Requires: Bash, curl
#
# For more information, visit: https://github.com/splunk/ShellSweep

#!/bin/bash

server=""
extensions=""
scan_directory=""

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -server)
            server="$2"
            shift
            shift
            ;;
        -extensions)
            extensions="$2"
            shift
            shift
            ;;
        -directory)
            scan_directory="$2"
            shift
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$server" ]; then
    echo "Error: Server URL is required. Use -server option."
    exit 1
fi

if [ -z "$scan_directory" ]; then
    echo "Error: Scan directory is required. Use -directory option."
    exit 1
fi

send_file() {
    local file_path="$1"
    local file_name=$(basename "$file_path")
    local file_size=$(stat -f%z "$file_path")
    local last_modified=$(date -r "$file_path" -u +"%Y-%m-%dT%H:%M:%SZ")
    local file_hash=$(shasum -a 256 "$file_path" | cut -d ' ' -f 1)
    local base64_content=$(base64 "$file_path")

    curl -X POST "$server/api/agent_results" \
         -H "Content-Type: application/json" \
         -d '{
             "agent_id": "'"$(hostname)"'",
             "computer_name": "'"$(hostname)"'",
             "results": [{
                 "FilePath": "'"$file_path"'",
                 "Hash": "'"$file_hash"'",
                 "LastModified": "'"$last_modified"'",
                 "FileSize": '"$file_size"',
                 "Content": "'"$base64_content"'"
             }]
         }'
}

if [ -z "$extensions" ]; then
    find "$scan_directory" -type f | while read file; do
        send_file "$file"
    done
else
    IFS=',' read -ra ext_array <<< "$extensions"
    for ext in "${ext_array[@]}"; do
        find "$scan_directory" -type f -name "*.$ext" | while read file; do
            send_file "$file"
        done
    done
fi

echo "Scan completed."
