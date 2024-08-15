#!/bin/bash

# Function to prompt the user for input
prompt_for_input() {
    read -p "$1 [$2]: " input
    echo "${input:-$2}"
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit
fi

# Detect package manager and install necessary packages
if command -v apt-get >/dev/null 2>&1; then
    echo "Installing necessary packages using apt-get..."
    apt-get update
    apt-get install -y python3 python3-pip supervisor
elif command -v yum >/dev/null 2>&1; then
    echo "Installing necessary packages using yum..."
    yum install -y epel-release
    yum install -y python3 python3-pip supervisor
elif command -v dnf >/dev/null 2>&1; then
    echo "Installing necessary packages using dnf..."
    dnf install -y python3 python3-pip supervisor
else
    echo "Unsupported package manager. Please install Python 3, pip, and supervisor manually."
    exit 1
fi

# Install required Python packages
pip3 install requests

# Prompt the user for Cloudflare authentication method
CLOUDFLARE_API_KEY=$(prompt_for_input "Enter your Cloudflare API key" "")
CLOUDFLARE_EMAIL=$(prompt_for_input "Enter your Cloudflare email" "")

# Prompt the user for domain names and IP addresses
declare -A DOMAIN_IP_MAP
while true; do
    DOMAIN=$(prompt_for_input "Enter a domain name to monitor" "")
    IP_ADDRESSES=$(prompt_for_input "Enter the IP addresses for $DOMAIN (comma-separated)" "")
    DOMAIN_IP_MAP[$DOMAIN]=$IP_ADDRESSES

    read -p "Do you want to add another domain? (y/n) " choice
    if [ "$choice" != "y" ]; then
        break
    fi
done

# Prompt the user for health check port
HEALTH_CHECK_PORT=$(prompt_for_input "Enter the port to be monitored" "14006")

# Prompt the user for health check timeout and interval
HEALTH_CHECK_TIMEOUT=$(prompt_for_input "Enter the health check timeout in seconds" "5")
HEALTH_CHECK_INTERVAL=$(prompt_for_input "Enter the health check interval in seconds" "60")

# Create the configuration file
CONFIG_FILE="config.json"
echo "Creating configuration file ($CONFIG_FILE)..."
cat <<EOL > $CONFIG_FILE
{
    "cloudflare": {
        "api_key": "$CLOUDFLARE_API_KEY",
        "email": "$CLOUDFLARE_EMAIL"
    },
    "records": [
EOL

for DOMAIN in "${!DOMAIN_IP_MAP[@]}"; do
    IP_LIST="["
    IFS=',' read -ra ADDR <<< "${DOMAIN_IP_MAP[$DOMAIN]}"
    for IP in "${ADDR[@]}"; do
        IP_LIST+="\"$IP\","
    done
    IP_LIST="${IP_LIST%,}]"

    cat <<EOL >> $CONFIG_FILE
        {
            "name": "$DOMAIN",
            "type": "A",
            "ip_addresses": $IP_LIST
        },
EOL
done

# Remove trailing comma and close JSON array and object
sed -i '$ s/,$//' $CONFIG_FILE

cat <<EOL >> $CONFIG_FILE
    ],
    "health_check": {
        "port": $HEALTH_CHECK_PORT,
        "timeout": $HEALTH_CHECK_TIMEOUT,
        "interval": $HEALTH_CHECK_INTERVAL
    }
}
EOL

echo "Configuration file created."

# Create the Python script
PYTHON_SCRIPT="monitor_dns.py"
echo "Creating Python script ($PYTHON_SCRIPT)..."
cat <<'EOL' > $PYTHON_SCRIPT
import json
import requests
import time
import socket
import logging
import sys

# Configure logging
logger = logging.getLogger("DNSMonitor")
logger.setLevel(logging.INFO)

# Create a file handler for logging
file_handler = logging.FileHandler("dns_monitor.log")
file_handler.setLevel(logging.INFO)

# Create a console handler for logging
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Create a logging format
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Load configuration from JSON file
def load_config():
    try:
        with open('config.json', 'r') as config_file:
            return json.load(config_file)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

# Get Zone ID dynamically using the Cloudflare API
def get_zone_id(auth, domain_name):
    headers = {
        'Content-Type': 'application/json'
    }
    
    # Determine the authentication method
    if 'api_token' in auth:
        headers['Authorization'] = f'Bearer {auth["api_token"]}'
    elif 'api_key' in auth and 'email' in auth:
        headers['X-Auth-Email'] = auth['email']
        headers['X-Auth-Key'] = auth['api_key']
    else:
        logger.error("Missing required authentication information.")
        sys.exit(1)
    
    try:
        response = requests.get(f'https://api.cloudflare.com/client/v4/zones?name={domain_name}', headers=headers)
        response.raise_for_status()
        result = response.json()
        if result['success'] and len(result['result']) > 0:
            return result['result'][0]['id']
        else:
            raise Exception(f"API returned success=False or no results for domain: {domain_name}")
    except requests.RequestException as e:
        logger.error(f"Error fetching Zone ID for {domain_name}: {e}")
        sys.exit(1)

# Check the health of a given IP and port using TCP connection
def check_health(ip_address, port, timeout):
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            logger.info(f"Health check passed for IP: {ip_address} on port {port}")
            return True
    except (socket.timeout, socket.error) as e:
        logger.warning(f"Health check failed for IP: {ip_address} on port {port} - {e}")
        return False

# Update DNS record through Cloudflare API
def update_dns_record(zone_id, record, ip_address, auth):
    headers = {
        'Content-Type': 'application/json'
    }
    
    # Determine the authentication method
    if 'api_token' in auth:
        headers['Authorization'] = f'Bearer {auth["api_token"]}'
    elif 'api_key' in auth and 'email' in auth:
        headers['X-Auth-Email'] = auth['email']
        headers['X-Auth-Key'] = auth['api_key']
    
    try:
        dns_records_response = requests.get(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record["name"]}&type={record["type"]}',
            headers=headers
        )
        dns_records_response.raise_for_status()
        dns_records = dns_records_response.json()
        if dns_records['success']:
            if dns_records['result']:
                dns_record = dns_records['result'][0]
                if dns_record['content'] != ip_address:
                    update_response = requests.put(
                        f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{dns_record["id"]}',
                        headers=headers,
                        json={'type': record['type'], 'name': record['name'], 'content': ip_address}
                    )
                    update_response.raise_for_status()
                    logger.info(f"Updated DNS record {record['name']} to IP {ip_address}")
                else:
                    logger.info(f"DNS record {record['name']} is already pointing to IP {ip_address}")
            else:
                logger.error(f"No DNS record found for {record['name']}")
        else:
            logger.error(f"Failed to fetch DNS records for {record['name']}. Response: {dns_records_response.text}")
    except requests.RequestException as e:
        logger.error(f"Error updating DNS record for {record['name']}: {e}")

# Main function to monitor DNS records
def main():
    config = load_config()
    auth = config['cloudflare']

    while True:
        for record in config['records']:
            try:
                # Get the root domain from the subdomain
                root_domain = record['name'].split('.', 1)[-1]
                zone_id = get_zone_id(auth, root_domain)
                
                # Process the record
                preferred_ip = None
                current_ip = None

                # Get the current DNS record IP
                headers = {
                    'Content-Type': 'application/json'
                }
                
                # Determine the authentication method
                if 'api_token' in auth:
                    headers['Authorization'] = f'Bearer {auth["api_token"]}'
                elif 'api_key' in auth and 'email' in auth:
                    headers['X-Auth-Email'] = auth['email']
                    headers['X-Auth-Key'] = auth['api_key']
                
                dns_records_response = requests.get(
                    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record["name"]}&type={record["type"]}',
                    headers=headers
                )
                dns_records_response.raise_for_status()
                dns_records = dns_records_response.json()
                if dns_records['success'] and dns_records['result']:
                    current_ip = dns_records['result'][0]['content']

                # Check health of IP addresses in priority order
                for ip_address in record['ip_addresses']:
                    if check_health(ip_address, config['health_check']['port'], config['health_check']['timeout']):
                        preferred_ip = ip_address
                        break

                # Update DNS record if necessary
                if preferred_ip and preferred_ip != current_ip:
                    update_dns_record(zone_id, record, preferred_ip, auth)
                else:
                    logger.info(f"No update needed for {record['name']}. Current IP is still valid or no preferred IP is healthy.")
            
            except requests.RequestException as e:
                logger.error(f"Error processing record for {record['name']}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}")

        time.sleep(config['health_check']['interval'])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("DNS monitor script terminated by user.")
    except Exception as e:
        logger.critical(f"Critical error occurred: {e}")
        sys.exit(1)
EOL

# Make the Python script executable
chmod +x $PYTHON_SCRIPT

# Set up Supervisor to manage the DNS Monitor script
SUPERVISOR_CONF="/etc/supervisord.d/dnsmonitor.conf"
echo "Creating Supervisor configuration ($SUPERVISOR_CONF)..."
cat <<EOL | sudo tee $SUPERVISOR_CONF > /dev/null
[program:dnsmonitor]
command=/usr/bin/python3 $(pwd)/$PYTHON_SCRIPT
directory=$(pwd)
autostart=true
autorestart=true
stderr_logfile=/var/log/dnsmonitor.err.log
stdout_logfile=/var/log/dnsmonitor.out.log
user=$(whoami)
EOL

# Reload Supervisor to apply the new configuration
echo "Reloading Supervisor..."
sudo supervisorctl reread
sudo supervisorctl update

echo "Setup complete. The DNS monitor is now running under Supervisor. You can manage it using the following commands:"
echo "  sudo supervisorctl status dnsmonitor"
echo "  sudo supervisorctl start dnsmonitor"
echo "  sudo supervisorctl stop dnsmonitor"
echo "  sudo supervisorctl restart dnsmonitor"
