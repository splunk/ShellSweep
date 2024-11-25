#!/usr/bin/env python3

"""
ShellSweep Agent

This script acts as an agent for the ShellSweep system. It scans specified directories
for files that may be potential webshells, using entropy analysis and other heuristics.
The script retrieves its configuration from a central server, performs the scan,
and reports any findings back to the server.

Usage:
    python3 shellsweep_agent.py <server_url>

Arguments:
    server_url: The URL of the ShellSweep server to connect to for configuration and reporting.

Example:
    python3 shellsweep_agent.py http://shellsweep-server:8080

To set up a daily cron job at 3 AM:
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/python3 /path/to/shellsweep_agent.py http://shellsweep-server:8080") | crontab -

Author: Michael Haag
Version: 1.0
License: Apache
"""
import argparse
import base64
import hashlib
import json
import math
import os
import sys
import uuid
from datetime import datetime, timezone

import requests
import yaml

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".shellsweep_config.yaml")
AGENT_ID_FILE = os.path.join(os.path.expanduser("~"), ".shellsweep_agent_id")
LAST_SCAN_FILE = os.path.join(os.path.expanduser("~"), ".shellsweep_last_scan")


def log_message(message):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")


def get_agent_id():
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r") as f:
            return f.read().strip()
    else:
        new_agent_id = str(uuid.uuid4())
        with open(AGENT_ID_FILE, "w") as f:
            f.write(new_agent_id)
        return new_agent_id


def get_configuration(server_url):
    try:
        config_url = f"{server_url}/api/agent_config"
        response = requests.get(config_url)
        response.raise_for_status()
        config = response.json()
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(config, f)
        return config
    except requests.RequestException as e:
        log_message(f"Failed to retrieve configuration: {e}")
        return None


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def check_file_entropy(file_path, config):
    with open(file_path, "rb") as f:
        content = f.read()
    entropy = calculate_entropy(content)
    log_message(f"File: {file_path}, Entropy: {entropy}")

    extension = os.path.splitext(file_path)[1]
    conditions = config["file_extensions"].get(extension, [])

    for condition in conditions:
        operation = condition["operation"]
        value = condition["value"]
        if operation == "gt" and entropy > value:
            return True
        elif operation == "lt" and entropy < value:
            return True
        elif operation == "eq" and entropy == value:
            return True
    return False


def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.fromisoformat(f.read().strip())
    return None


def set_last_scan_time():
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(datetime.now(timezone.utc).isoformat())


def scan_directories(config, last_scan_time):
    results = []
    for dir_path in config["directory_paths"]:
        log_message(f"Scanning directory: {dir_path}")
        if not os.path.isdir(dir_path):
            log_message(f"Warning: Directory not found: {dir_path}")
            continue

        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                extension = os.path.splitext(file)[1]

                if extension not in config["file_extensions"]:
                    continue

                if any(
                    file_path.startswith(exclude) for exclude in config["exclude_paths"]
                ):
                    continue

                file_stat = os.stat(file_path)
                file_mtime = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)

                if last_scan_time and file_mtime <= last_scan_time:
                    continue

                file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
                if file_hash in config["ignore_hashes"]:
                    log_message(f"Ignoring file with known hash: {file_path}")
                    continue

                if check_file_entropy(file_path, config):
                    results.append(
                        {
                            "FilePath": file_path,
                            "Hash": file_hash,
                            "LastModified": file_mtime.isoformat(),
                            "FileSize": file_stat.st_size,
                        }
                    )

    return results


def send_results(results, server_url):
    agent_id = get_agent_id()
    computer_name = os.uname().nodename

    total_files = len(results)
    successful_uploads = 0
    failed_uploads = 0

    for result in results:
        with open(result["FilePath"], "rb") as f:
            content = base64.b64encode(f.read()).decode("utf-8")

        payload = {
            "agent_id": agent_id,
            "computer_name": computer_name,
            "results": [
                {
                    "FilePath": result["FilePath"],
                    "Hash": result["Hash"],
                    "LastModified": result["LastModified"],
                    "FileSize": result["FileSize"],
                    "Content": content,
                }
            ],
        }

        try:
            response = requests.post(f"{server_url}/api/agent_results", json=payload)
            response.raise_for_status()
            successful_uploads += 1
            log_message(f"File sent successfully: {result['FilePath']}")
        except requests.RequestException as e:
            failed_uploads += 1
            log_message(f"Failed to send file: {result['FilePath']}. Error: {e}")

    log_message(
        f"Upload summary: {successful_uploads}/{total_files} files sent successfully, {failed_uploads} failed."
    )


def send_agent_checkin(server_url):
    agent_id = get_agent_id()
    computer_name = os.uname().nodename

    payload = {"agent_id": agent_id, "computer_name": computer_name}

    try:
        response = requests.post(f"{server_url}/api/agent_checkin", json=payload)
        response.raise_for_status()
        log_message("Agent check-in successful")
    except requests.RequestException as e:
        log_message(f"Failed to send agent check-in: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="ShellSweep Agent - Scans directories for potential webshells and reports findings to a central server."
    )
    parser.add_argument(
        "server_url",
        help="The URL of the ShellSweep server to connect to for configuration and reporting.",
    )
    args = parser.parse_args()

    config = get_configuration(args.server_url)
    if config:
        log_message("Configuration loaded successfully")
        send_agent_checkin(args.server_url)

        last_scan_time = get_last_scan_time()
        if last_scan_time:
            log_message(
                f"Performing subsequent scan for files modified after {last_scan_time.isoformat()}"
            )
        else:
            log_message("Performing initial scan of all files")

        log_message("Starting directory scan...")
        results = scan_directories(config, last_scan_time)
        log_message(f"Scan completed. Found {len(results)} potential issues.")

        if results:
            log_message("Sending results to server...")
            send_results(results, args.server_url)
        else:
            log_message("No issues found. Skipping result submission.")

        set_last_scan_time()
    else:
        log_message(
            "Failed to retrieve configuration. Using last known good configuration."
        )
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as f:
                config = yaml.safe_load(f)
            log_message("Starting scan with last known configuration...")
            results = scan_directories(config, None)
            log_message(f"Scan completed. Found {len(results)} potential issues.")

            if results:
                log_message("Sending results to server...")
                send_results(results, args.server_url)
            else:
                log_message("No issues found. Skipping result submission.")

            set_last_scan_time()
        else:
            log_message("Error: No configuration available. Exiting.")
            sys.exit(1)


if __name__ == "__main__":
    main()
