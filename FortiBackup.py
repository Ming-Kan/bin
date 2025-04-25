#!/usr/bin/env python3
"""FortiBackup.py - Script to backup FortiGate configuration via API

This script connects to one or multiple FortiGate devices via their APIs and downloads
the configuration backup files. It can backup a single device using command-line options
or multiple devices using a configuration file.

Usage:
  python FortiBackup.py [options]

Options:
  --host HOST         FortiGate IP address or hostname
  --port PORT         FortiGate API port (default: 8443)
  --token TOKEN       API access token
  --verify-ssl        Enable SSL certificate verification
  --backup-dir DIR    Directory to save backup files
  --filename NAME     Base filename for backups (default: api_configbackup.conf)
  --config-file FILE  Path to config file with multiple FortiGate devices (JSON or YAML)
  --verbose           Enable verbose logging

Environment Variables (for single device mode):
  FORTI_API_HOST      FortiGate IP address or hostname
  FORTI_API_PORT      FortiGate API port
  FORTI_API_TOKEN     API access token
  FORTI_VERIFY_SSL    Enable SSL certificate verification (true/false)
  FORTI_BACKUP_DIR    Directory to save backup files
  FORTI_BACKUP_FILENAME Base filename for backups

Config File Format (JSON example):
  [
    {
      "api_host": "192.168.1.1",
      "api_port": "8443",
      "api_token": "your-api-token-1",
      "verify_ssl": false,
      "backup_dir": "C:\\bin\\backups\\firewall1",
      "backup_filename": "backup.conf",
      "hostname": "FortiGate-FW1"  // Optional: manually specify hostname
    },
    {
      "api_host": "192.168.1.2",
      "api_token": "your-api-token-2",
      "backup_dir": "C:\\bin\\backups\\firewall2"
    }
  ]

Dependencies:
- requests: HTTP library for making API calls (pip install requests)
- pyyaml: YAML parser for config files (pip install pyyaml) - only needed for YAML config files
"""

import os
import sys
import logging
import argparse
import json
import requests
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='FortiBackup - Script to backup FortiGate configuration via API')
    parser.add_argument('--host', help='FortiGate IP address or hostname')
    parser.add_argument('--port', default=8443, type=int, help='FortiGate API port (default: 8443)')
    parser.add_argument('--token', help='API access token')
    parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL certificate verification')
    parser.add_argument('--backup-dir', default='backups', help='Directory to save backup files')
    parser.add_argument('--filename', default='backup.conf', help='Base filename for backups')
    parser.add_argument('--config-file', help='Path to config file with multiple FortiGate devices (JSON or YAML)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    return parser.parse_args()

# Print help and exit when required parameters are missing
def print_help_and_exit():
    parser = argparse.ArgumentParser(
        description="FortiGate Configuration Backup Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.print_help()
    print("\nError: Missing required parameters. You must specify either:")
    print("  1. A config file with --config-file")
    print("  2. Both --host and --token for a single device")
    print("\nExamples:")
    print("  python FortiBackup.py --config-file fortigate_devices.json")
    print("  python FortiBackup.py --host 192.168.1.1 --token your-api-token")
    sys.exit(1)

# Main function
def main():
    args = parse_arguments()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    logging.info('Starting FortiBackup script')
    
    if args.config_file:
        # Process multiple devices from config file
        config = read_config_file(args.config_file)
        logging.debug(f"Config file content: {config}")
        
        success_count = 0
        failure_count = 0
        
        for i, device in enumerate(config):
            host = device.get('api_host')
            port = device.get('api_port', args.port)
            token = device.get('api_token')
            verify_ssl = device.get('verify_ssl', args.verify_ssl)
            backup_dir = device.get('backup_dir', args.backup_dir)
            filename = device.get('backup_filename', args.filename)
            hostname = device.get('hostname')
            
            # Check required parameters
            if not host or not token:
                logging.error(f"Device #{i+1} is missing required parameters (api_host or api_token)")
                failure_count += 1
                continue
                
            logging.info(f"Processing device {i+1}/{len(config)}: {host}")
            
            try:
                if backup_fortigate(host, port, token, verify_ssl, backup_dir, filename, hostname):
                    success_count += 1
                else:
                    failure_count += 1
            except Exception as e:
                logging.error(f"Unexpected error processing device {host}: {e}")
                failure_count += 1
        
        # Report results
        logging.info(f"Backup process completed. Successful: {success_count}, Failed: {failure_count}")
        
        # Exit with error if any device failed
        if failure_count > 0:
            sys.exit(1)
    else:
        # Process single device
        host = args.host
        token = args.token
        
        # Check required parameters
        if not host or not token:
            print_help_and_exit()
            
        backup_fortigate(host, args.port, token, args.verify_ssl, args.backup_dir, args.filename)

# Read configuration file if provided
def read_config_file(config_file):
    if not os.path.exists(config_file):
        logging.error(f"Config file {config_file} does not exist")
        sys.exit(1)
    
    try:
        with open(config_file, 'r') as file:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                import yaml
                config = yaml.safe_load(file)
            elif config_file.endswith('.json'):
                config = json.load(file)
            else:
                logging.error("Unsupported config file format. Use JSON or YAML.")
                sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading config file {config_file}: {e}")
        sys.exit(1)
    
    return config

# Get FortiGate hostname if not provided
def get_fortigate_hostname(host, port, token, verify_ssl):
    logging.debug(f"Attempting to get hostname for FortiGate at {host}:{port}")
    
    # Define possible hostname endpoints to try
    hostname_endpoints = [
        "/api/v2/cmdb/system/global",
        "/api/v2/monitor/system/status",
        "/api/v2/cmdb/system/settings"
    ]
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Try each endpoint until we get the hostname
    for endpoint in hostname_endpoints:
        url = f"https://{host}:{port}{endpoint}"
        
        try:
            logging.debug(f"Trying hostname endpoint: {url}")
            response = requests.get(url, headers=headers, verify=verify_ssl, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Different endpoints have different response structures
                hostname = None
                
                # Try to extract hostname from different response structures
                if 'results' in data:
                    # For global settings endpoint
                    for item in data['results']:
                        if isinstance(item, dict):
                            if 'hostname' in item:
                                hostname = item['hostname']
                                break
                            elif 'name' in item and item['name'] == 'hostname' and 'value' in item:
                                hostname = item['value']
                                break
                
                # For system status endpoint
                elif 'status' in data and isinstance(data['status'], dict):
                    if 'hostname' in data['status']:
                        hostname = data['status']['hostname']
                
                if hostname:
                    logging.info(f"Retrieved FortiGate hostname: {hostname}")
                    return hostname
                
        except Exception as e:
            logging.debug(f"Error getting hostname from endpoint {endpoint}: {e}")
    
    # If we couldn't get the hostname, use the IP address
    logging.warning(f"Could not retrieve FortiGate hostname. Using IP address {host} instead.")
    return host

# Backup logic
def backup_fortigate(host, port, token, verify_ssl, backup_dir, filename, hostname=None):
    logging.info(f"Backing up FortiGate at {host}:{port}")
    
    # Get hostname if not provided
    if not hostname:
        hostname = get_fortigate_hostname(host, port, token, verify_ssl)
    
    # Define possible backup endpoints to try
    backup_endpoints = [
        "/api/v2/monitor/system/config/backup?scope=global",
        "/api/v2/cmdb/system/backup/backup?destination=file&scope=global",
        "/api/v2/monitor/system/config/backup?scope=global&destination=file",
        "/api/v2/cmdb/system/config/running"
    ]
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Disable SSL warnings if verification is disabled
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Try each backup endpoint until one works
    for endpoint in backup_endpoints:
        url = f"https://{host}:{port}{endpoint}"
        
        try:
            logging.debug(f"Trying backup endpoint: {url}")
            response = requests.get(url, headers=headers, verify=verify_ssl, timeout=30)
            
            # Skip to next endpoint if we get a 404
            if response.status_code == 404:
                logging.warning(f"Endpoint {endpoint} not found (404). Trying another endpoint...")
                continue
                
            # Handle other error codes
            response.raise_for_status()
            
            # Check if the response contains actual configuration data
            if len(response.content) < 100:  # Arbitrary small size that's unlikely for a real config
                logging.warning(f"Response from {endpoint} seems too small to be a configuration backup. Trying another endpoint...")
                continue
            
            # Ensure the backup directory exists
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create a timestamped filename with hostname
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{hostname}_{timestamp}_{filename}"
            backup_path = os.path.join(backup_dir, backup_filename)
            
            # Write the backup file
            with open(backup_path, 'wb') as file:
                file.write(response.content)
            
            logging.info(f"Backup successfully saved to {backup_path}")
            return True
            
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Connection error: {e}")
            logging.error("Please check if the FortiGate device is reachable and the host/port are correct")
            return False
        except requests.exceptions.Timeout as e:
            logging.error(f"Request timed out: {e}")
            logging.error("The FortiGate device took too long to respond")
            return False
        except requests.exceptions.HTTPError as e:
            logging.warning(f"HTTP error with endpoint {endpoint}: {e}")
            # Try the next endpoint
            continue
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed for endpoint {endpoint}: {e}")
            # Try the next endpoint
            continue
        except Exception as e:
            logging.error(f"Unexpected error backing up FortiGate at {host}:{port}: {e}")
            return False
    
    # If we've tried all endpoints and none worked
    logging.error("All backup endpoints failed. Please check your FortiGate device and configuration.")
    return False

if __name__ == '__main__':
    main()
