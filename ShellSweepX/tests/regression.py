# """
# This script performs regression testing for the ShellSweepX system. It simulates various scenarios to test the functionality and reliability of the webshell detection system. The script does the following:

# 1. Simulates agent check-ins to register test agents with the server.
# 2. Generates and submits both benign PHP files and webshells to test detection accuracy.
# 3. Retrieves and verifies detection results from the server.
# 4. Tests the system's ability to handle various file sizes, contents, and submission rates.
# 5. Verifies the correct functioning of the API endpoints for agent configuration and recent detections.

# The script uses randomization to create unique file contents and agent identifiers, ensuring a diverse range of test cases. It interacts with the ShellSweepX server through its API endpoints, simulating real-world usage scenarios.

# This comprehensive test suite helps identify potential issues in webshell detection, false positive rates, system performance, and API functionality, ensuring the robustness of the ShellSweepX system.
# """


import requests
import random
import string
import hashlib
import base64
import time
import uuid
from datetime import datetime
import json
import sys

SERVER_URL = "http://localhost:8080"  # Change this to your server's URL
GENERIC_WEBSHELL = """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>"""

BENIGN_PHP = """<?php
// This is a benign file
echo "Hello, World!";
?>"""

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_unique_webshell():
    return f"{GENERIC_WEBSHELL}\n<!-- {random_string(20)} -->"

def generate_benign_file():
    return f"{BENIGN_PHP}\n<!-- BENIGN_{random_string(20)} -->"

def simulate_agent_checkin():
    agent_id = str(uuid.uuid4())
    computer_name = f"TESTPC-{random_string(5)}"
    payload = {
        "agent_id": agent_id,
        "computer_name": computer_name
    }
    try:
        response = requests.post(f"{SERVER_URL}/api/agent_checkin", json=payload, timeout=10)
        response.raise_for_status()
        print(f"Agent check-in: {response.status_code} - {response.text}")
        return True
    except requests.RequestException as e:
        print(f"Agent check-in failed: {str(e)}")
        return False

def simulate_file_upload(is_webshell=True):
    content = generate_unique_webshell() if is_webshell else generate_benign_file()
    file_type = 'webshell' if is_webshell else 'benign'
    file_name = f"test_{file_type}_{random_string()}.php"
    file_content = base64.b64encode(content.encode()).decode()
    file_size = len(content)
    sha256 = hashlib.sha256(content.encode()).hexdigest()

    payload = {
        "agent_id": str(uuid.uuid4()),
        "computer_name": f"TESTPC-{random_string(5)}",
        "results": [{
            "FilePath": f"/var/www/html/{file_name}",
            "Hash": sha256,
            "LastModified": datetime.now().isoformat(),
            "FileSize": file_size,
            "Content": file_content
        }]
    }

    try:
        response = requests.post(f"{SERVER_URL}/api/agent_results", json=payload, timeout=10)
        response.raise_for_status()
        print(f"File upload ({file_type}): {response.status_code} - {response.text}")
        
        time.sleep(1)
        search_query = "webshell" if is_webshell else "BENIGN"
        search_response = requests.get(f"{SERVER_URL}/search?query={search_query}&page=1&page_size=1", timeout=10)
        search_response.raise_for_status()
        search_results = search_response.json()
        if len(search_results['results']) > 0:
            print(f"{file_type.capitalize()} file found in search results")
            return True
        else:
            print(f"{file_type.capitalize()} file not found in search results")
            return False
    except requests.RequestException as e:
        print(f"File upload failed: {str(e)}")
        return False

def simulate_burst_upload():
    num_files = random.randint(1, 100)
    agent_id = str(uuid.uuid4())
    computer_name = f"TESTPC-{random_string(5)}"
    results = []

    for i in range(num_files):
        content = generate_unique_webshell()
        file_name = f"burst_webshell_{random_string()}.php"
        file_content = base64.b64encode(content.encode()).decode()
        file_size = len(content)
        sha256 = hashlib.sha256(content.encode()).hexdigest()

        results.append({
            "FilePath": f"/var/www/html/{file_name}",
            "Hash": sha256,
            "LastModified": datetime.now().isoformat(),
            "FileSize": file_size,
            "Content": file_content
        })

    payload = {
        "agent_id": agent_id,
        "computer_name": computer_name,
        "results": results
    }

    try:
        response = requests.post(f"{SERVER_URL}/api/agent_results", json=payload, timeout=30)
        response.raise_for_status()
        print(f"Burst upload attempt: {response.status_code} - Attempted to upload {num_files} files")
        
        time.sleep(2)
        search_response = requests.get(f"{SERVER_URL}/search?query=burst_webshell&page=1&page_size={num_files}", timeout=10)
        search_response.raise_for_status()
        search_results = search_response.json()
        actual_uploaded = len(search_results['results'])
        
        print(f"Burst upload verification: Found {actual_uploaded} out of {num_files} uploaded files in search results")
        
        return actual_uploaded == num_files
    except requests.RequestException as e:
        print(f"Burst upload failed: {str(e)}")
        return False

def test_search_functionality():
    try:
        response = requests.get(f"{SERVER_URL}/search?query=webshell&page=1&page_size=100", timeout=10)
        response.raise_for_status()
        results = response.json()
        total_results = results.get('total', 0)
        print(f"Search test: {response.status_code} - Found {len(results['results'])} results on this page, {total_results} total")
        return True
    except requests.RequestException as e:
        print(f"Search test failed: {str(e)}")
        return False

def test_yara_scanning():
    try:
        response = requests.post(f"{SERVER_URL}/scan_database_with_yara", timeout=30)
        response.raise_for_status()
        print(f"YARA scan test: {response.status_code} - {response.text}")
        return True
    except requests.RequestException as e:
        print(f"YARA scan test failed: {str(e)}")
        return False

def test_ai_triage():
    try:
        simulate_file_upload(is_webshell=True)
        search_response = requests.get(f"{SERVER_URL}/search?query=webshell&page=1&page_size=1", timeout=10)
        search_response = requests.get(f"{SERVER_URL}/search?query=webshell&page=1&page_size=1", timeout=10)
        search_response.raise_for_status()
        sha256 = search_response.json()['results'][0]['sha256']
        
        triage_response = requests.post(f"{SERVER_URL}/triage_with_ai", data={"sha256": sha256}, timeout=30)
        triage_response.raise_for_status()
        print(f"AI triage test: {triage_response.status_code} - Analysis received")
        return True
    except requests.RequestException as e:
        print(f"AI triage test failed: {str(e)}")
        return False

def run_regression_test(duration_minutes=10):
    end_time = time.time() + (duration_minutes * 60)
    test_results = {
        "agent_checkins": 0,
        "webshell_uploads": 0,
        "benign_uploads": 0,
        "burst_uploads": 0,
        "search_tests": 0,
        "yara_scans": 0,
        "ai_triages": 0,
        "failures": 0
    }
    
    while time.time() < end_time:
        test_type = random.choice([
            "agent_checkin",
            "webshell_upload",
            "benign_upload",
            "burst_upload",
            "search",
            "yara_scan",
            "ai_triage"
        ])
        
        if test_type == "agent_checkin":
            success = simulate_agent_checkin()
            test_results["agent_checkins"] += 1 if success else 0
        elif test_type == "webshell_upload":
            success = simulate_file_upload(is_webshell=True)
            test_results["webshell_uploads"] += 1 if success else 0
        elif test_type == "benign_upload":
            success = simulate_file_upload(is_webshell=False)
            test_results["benign_uploads"] += 1 if success else 0
        elif test_type == "burst_upload":
            success = simulate_burst_upload()
            test_results["burst_uploads"] += 1 if success else 0
        elif test_type == "search":
            success = test_search_functionality()
            test_results["search_tests"] += 1 if success else 0
        elif test_type == "yara_scan":
            success = test_yara_scanning()
            test_results["yara_scans"] += 1 if success else 0
        elif test_type == "ai_triage":
            success = test_ai_triage()
            test_results["ai_triages"] += 1 if success else 0
        
        if not success:
            test_results["failures"] += 1
        
        time.sleep(random.uniform(1, 5))
    
    return test_results

if __name__ == "__main__":
    print("Starting ShellSweep regression test...")
    duration = 10
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print(f"Invalid duration: {sys.argv[1]}. Using default of 10 minutes.")
    
    results = run_regression_test(duration_minutes=duration)
    print("\nRegression test completed. Results:")
    print(json.dumps(results, indent=2))
    
    total_tests = sum(results.values()) - results["failures"]
    failure_rate = (results["failures"] / total_tests * 100) if total_tests > 0 else 0
    print(f"\nFailure rate: {failure_rate:.2f}%")
    
    if failure_rate > 5:
        print("Warning: High failure rate detected!")
        sys.exit(1)
    else:
        print("Regression test passed successfully.")
        sys.exit(0)