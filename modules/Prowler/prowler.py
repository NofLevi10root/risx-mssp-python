import requests
import urllib3
import json
import sys
import time
import os
import argparse
from datetime import datetime
import random
import traceback

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create a session with SSL verification disabled
session = requests.Session()
session.verify = False

def authenticate(BASE_URL, USERNAME, PASSWORD, logger):
    """Authenticate and get access token"""
    logger.info("[*] Authenticating to Prowler API...")
    
    auth_url = f"{BASE_URL}/api/v1/tokens"
    auth_data = {
        "email": USERNAME,
        "password": PASSWORD
    }
    
    try:
        response = session.post(auth_url, data=auth_data)
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data["data"]["attributes"]["access"]
        
        # Set token in session headers
        session.headers.update({"Authorization": f"Bearer {access_token}"})
        logger.info("[+] Authentication successful!")
        return True
        
    except Exception as e:
        logger.info(f"[!] Authentication failed: {e}")
        return False

# FUNCTION 1: Start a scan and return scan ID
def start_scan(BASE_URL, USERNAME, PASSWORD, logger):
    """Start a new scan and return the task ID"""
    logger.info("[*] Starting a new scan...")
    
    # Get cloud account and provider
    resource_id, provider_id = get_cloud_accounts(BASE_URL, USERNAME, PASSWORD, logger)
    if not resource_id or not provider_id:
        return None
    
    try:
        scan_url = f"{BASE_URL}/api/v1/scans"
        
        # Minimal JSON:API payload with provider relationship
        scan_payload = {
            "data": {
                "type": "scans",
                "relationships": {
                    "provider": {
                        "data": {
                            "type": "providers",
                            "id": provider_id
                        }
                    }
                }
            }
        }
        
        # Set the correct content type for JSON:API
        headers = {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json"
        }
        
        # Combine with existing headers (including auth token)
        merged_headers = {**session.headers, **headers}
        
        # Make the request
        response = session.post(scan_url, json=scan_payload, headers=merged_headers)
        response.raise_for_status()
        
        # Parse the response
        scan_data = response.json()
        logger.info("scan data:" + str(scan_data))
        task_id = scan_data.get("data", {}).get("id")
        scan_id = scan_data.get("data", {}).get("attributes").get("task_args").get("scan_id")
        
        if task_id:
            logger.info(f"[+] Scan started successfully! Task ID: {task_id}")
            # Add a delay after creating the scan to give the server time to initialize
            logger.info("[*] Waiting 5 seconds for task initialization...")
            time.sleep(5)
            return task_id,scan_id
        else:
            logger.info("[!] Scan started but no task ID was returned")
            return None
            
    except Exception as e:
        logger.info(f"[!] Failed to start scan: {e}")
        if 'response' in locals() and hasattr(response, 'text'):
            logger.info(f"[!] Response: {response.text}")
        return None

def get_cloud_accounts(BASE_URL, USERNAME, PASSWORD, logger):
    """Get available cloud accounts"""
    logger.info("[*] Retrieving cloud accounts...")
    
    try:
        accounts_url = f"{BASE_URL}/api/v1/resources"
        response = session.get(accounts_url)
        response.raise_for_status()
        
        accounts_data = response.json()
        accounts = accounts_data.get("data", [])
        
        # logger.info all available accounts
        if accounts:
            logger.info("[+] Available cloud accounts:")
            for i, account in enumerate(accounts):
                account_id = account.get("id")
                name = account.get("attributes", {}).get("name", "Unknown")
                provider_id = account.get("relationships", {}).get("provider", {}).get("data", {}).get("id", "Unknown")
                logger.info(f"  {i+1}. {account_id} - {name} (Provider ID: {provider_id})")
            
            # Use the first account
            account_id = accounts[0]["id"]
            provider_id = accounts[0].get("relationships", {}).get("provider", {}).get("data", {}).get("id")
            logger.info(f"[+] Using account ID: {account_id}, Provider ID: {provider_id}")
            return account_id, provider_id
        else:
            logger.info("[!] No cloud accounts found")
            return None, None
            
    except Exception as e:
        logger.info(f"[!] Failed to retrieve cloud accounts: {e}")
        return None, None

# FUNCTION 2: Get task status by ID
def get_task_status(task_id, logger):
    """Get the status of a task by its ID"""
    logger.info(f"[*] Checking status of task {task_id}...")
    
    try:
        # Use the tasks endpoint
        status_url = f"{BASE_URL}/api/v1/tasks/{task_id}"
        
        # Set headers
        headers = {
            "Accept": "application/vnd.api+json"
        }
        
        # Combine with existing headers
        merged_headers = {**session.headers, **headers}
        
        # Make the request
        response = session.get(status_url, headers=merged_headers)
        response.raise_for_status()
        
        # Parse the response
        status_data = response.json()
        
        # Extract status from 'state' or 'status' fields
        attributes = status_data.get("data", {}).get("attributes", {})
        status = attributes.get("state", attributes.get("status", "unknown"))
        
        # Also look in nested result object
        if status == "unknown" and "result" in attributes:
            result = attributes.get("result", {})
            status = result.get("state", result.get("status", "unknown"))
        
        logger.info(f"[+] Task status: {status}")
        
        return status
        
    except Exception as e:
        logger.info(f"[!] Failed to check task status: {e}")
        if 'response' in locals() and hasattr(response, 'text'):
            logger.info(f"[!] Response: {response.text}")
        return "error"

# FUNCTION 3: Get task results and download files
def get_task_results(scan_id, logger):
    """Get the results of a completed scan and download them"""
    logger.info(f"[*] Retrieving results for task {scan_id}...")
    
    try:
        
        # Try multiple possible endpoints for downloading results
        download_endpoints = [
            f"{BASE_URL}/api/v1/scans/{scan_id}",
        ]
        
        # Set headers for download request
        headers = {
            "Accept": "application/zip, application/json, application/vnd.api+json",
            "Accept-Encoding": "gzip, deflate"
        }
        
        # Combine with existing headers
        merged_headers = {**session.headers, **headers}
        
        success = False
        
        for endpoint_url in download_endpoints:
            try:
                logger.info(f"[*] Trying endpoint: {endpoint_url}")
                response = session.get(endpoint_url, headers=merged_headers, stream=True)
                logger.info("task results response:" + str(response))
                if response.status_code == 200:
                    content_type = response.json()
                    logger.info(content_type)
            except Exception as e:
                logger.info("Endpoint error:" + str(e))
        
        return success
        
    except Exception as e:
        logger.info(f"[!] Failed to retrieve task results: {e}")
        return False


# Main execution
def run_prowler(row, config_data, logger):
    # Parse command line arguments
    try:
        row["UniqueID"] = str(random.randint(9000000, 99999999))
        logger.info("Inside run_prowler!")
        timeout = row["ExpireDate"]
        BASE_URL = "https://" + config_data['ClientData']['API']['Prowler']['IP'] + ":8629"
        USERNAME = config_data['ClientData']['API']['Prowler']['Username'] 
        PASSWORD = config_data['ClientData']['API']['Prowler']['Password']
        check_interval = 10
        # Step 1: Start a scan and get its task ID (or use provided task ID)
        # Authenticate for existing task
        
        if not authenticate(BASE_URL, USERNAME, PASSWORD, logger):
            logger.info("[!] Failed to authenticate")
            sys.exit(1)

        task_id, scan_id = start_scan(BASE_URL, USERNAME, PASSWORD, logger)
        if not task_id:
            logger.info("[!] Failed to start scan")
            sys.exit(1)

        #task_id = "f1a32a5d-bd23-453a-b3e4-fbd74e8c97b8"
        #scan_id = "01973529-ca6e-7113-a162-c686f28be57d"
        logger.info(f"[*] Monitoring task {task_id}...")
        logger.info(f"[*] Timeout set to {timeout} seconds")
        logger.info(f"[*] Will check status every {check_interval} seconds")
        
        # Step 2: Loop with check interval delay checking status until complete or timeout
        completed_statuses = ["completed", "finished", "done", "success", "succeeded"]
        error_statuses = ["error", "failed", "terminated", "cancelled"]
        
        # Set a timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check task status
            status = get_task_status(task_id, logger)
            
            # If status indicates completion, exit loop
            if status.lower() in completed_statuses:
                logger.info(f"[+] Task {task_id} completed successfully!")
                break
                
            # If status indicates error, exit with error
            if status.lower() in error_statuses:
                logger.info(f"[!] Task {task_id} failed with status: {status}")
                # Still try to get results
                break
                
            # Otherwise wait and check again
            elapsed = int(time.time() - start_time)
            remaining = timeout - elapsed
            logger.info(f"[*] Task in progress with status: {status}. Time elapsed: {elapsed}s, remaining: {remaining}s")
            logger.info(f"[*] Checking again in {check_interval} seconds...")
            time.sleep(check_interval)
        else:
            # Timeout reached
            logger.info(f"[!] Timeout of {timeout} seconds reached waiting for task {task_id} to complete")
            logger.info("[*] Attempting to retrieve results anyway...")

        row["Status"] = "Complete"
        row["ExpireDate"] =  datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        return row
    except Exception as e:
        logger.info("Prowler crush:" + str(e))
        logger.error(traceback.format_exc())
        row["Status"] = "Failed"
        row["ExpireDate"] =  datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        return row
    # Step 3: Get and download the results
    """
    logger.info(f"\n[*] Attempting to retrieve and download results for task {task_id}...")
    if get_task_results(scan_id, args.output):
        logger.info(f"\n[+] Process completed successfully!")
        logger.info(f"[+] Results saved with base filename: {args.output}")
        logger.info(f"[+] Check the current directory for downloaded files.")
    else:
        logger.info(f"\n[!] Failed to retrieve results for task {task_id}")
        logger.info("[*] You may need to check the Prowler API documentation for the correct endpoints.")
        logger.info(f"[*] API docs should be available at: {BASE_URL}/api/v1/docs")
        sys.exit(1)
    """