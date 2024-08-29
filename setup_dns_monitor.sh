#!/bin/bash

CONFIG_FILE="config.json"
PYTHON_SCRIPT="monitor_dns.py"
LANGUAGE="en"

function prompt_non_empty {
    local prompt_message="$1"
    local input_var

    while true; do
        read -p "$prompt_message" input_var
        if [ -z "$input_var" ]; then
            echo "This field cannot be empty. Please enter a valid value."
        else
            echo "$input_var"
            break
        fi
    done
}

function create_config {
    if [ "$LANGUAGE" == "zh" ]; then
        echo "正在创建新的 config.json..."
    else
        echo "Creating new config.json..."
    fi
    
    echo "{}" > $CONFIG_FILE

    cloudflare_api_key=$(prompt_non_empty "请输入您的 Cloudflare API 密钥:")
    cloudflare_email=$(prompt_non_empty "请输入您的 Cloudflare 电子邮件:")
    telegram_bot_token=$(prompt_non_empty "请输入您的 Telegram bot token (可选):")
    telegram_chat_id=$(prompt_non_empty "请输入您的 Telegram chat ID (可选):")
    telegram_api_url=$(prompt_non_empty "请输入您的自定义 Telegram API URL (可选):")
    health_check_port=$(prompt_non_empty "请输入要监控的端口:")
    health_check_timeout=$(prompt_non_empty "请输入健康检查的超时时间（秒）:")
    health_check_interval=$(prompt_non_empty "请输入健康检查的间隔时间（秒）:")
    fail_threshold=$(prompt_non_empty "请输入失败阈值（失败几次后更新 DNS）:")

    jq ". + {
        \"cloudflare\": {
            \"api_key\": \"$cloudflare_api_key\",
            \"email\": \"$cloudflare_email\"
        },
        \"telegram\": {
            \"enabled\": true,
            \"bot_token\": \"$telegram_bot_token\",
            \"chat_id\": \"$telegram_chat_id\",
            \"api_url\": \"$telegram_api_url\"
        },
        \"health_check\": {
            \"port\": $health_check_port,
            \"timeout\": $health_check_timeout,
            \"interval\": $health_check_interval,
            \"fail_threshold\": $fail_threshold
        },
        \"records\": []
    }" $CONFIG_FILE > temp.json && mv temp.json $CONFIG_FILE

    if [ "$LANGUAGE" == "zh" ]; then
        echo "配置创建成功!"
    else
        echo "Configuration created successfully!"
    fi
}

function list_domains {
    jq '.records[] | .name' $CONFIG_FILE
}

function modify_domain {
    if [ "$LANGUAGE" == "zh" ]; then
        echo "请输入要修改的域名:"
    else
        echo "Enter the domain to modify:"
    fi
    read domain

    index=$(jq ".records | map(.name == \"$domain\") | index(true)" $CONFIG_FILE)

    if [ "$index" == "null" ]; then
        if [ "$LANGUAGE" == "zh" ]; then
            echo "未找到域名。"
        else
            echo "Domain not found."
        fi
        return
    fi

    if [ "$LANGUAGE" == "zh" ]; then
        echo "请输入新的 IP 地址（逗号分隔）:"
    else
        echo "Enter new IP addresses (comma-separated):"
    fi
    read new_ips

    jq ".records[$index].ip_addresses = [$(echo $new_ips | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')]" $CONFIG_FILE > temp.json && mv temp.json $CONFIG_FILE
    if [ "$LANGUAGE" == "zh" ]; then
        echo "域名 IP 地址更新成功!"
    else
        echo "Domain IP addresses updated successfully!"
    fi
}

function delete_domain {
    if [ "$LANGUAGE" == "zh" ]; then
        echo "请输入要删除的域名:"
    else
        echo "Enter the domain to delete:"
    fi
    read domain

    jq ".records |= map(select(.name != \"$domain\"))" $CONFIG_FILE > temp.json && mv temp.json $CONFIG_FILE
    if [ "$LANGUAGE" == "zh" ]; then
        echo "域名删除成功!"
    else
        echo "Domain deleted successfully!"
    fi
}

function add_domain {
    if [ "$LANGUAGE" == "zh" ]; then
        echo "请输入域名:"
    else
        echo "Enter the domain name:"
    fi
    read domain

    if [ "$LANGUAGE" == "zh" ]; then
        echo "请输入记录类型（例如 A, CNAME）:"
    else
        echo "Enter the record type (e.g., A, CNAME):"
    fi
    read record_type

    if [ "$LANGUAGE" == "zh" ]; then
        echo "请输入 IP 地址（逗号分隔）:"
    else
        echo "Enter the IP addresses (comma-separated):"
    fi
    read ip_addresses

    jq ".records += [{
        \"name\": \"$domain\",
        \"type\": \"$record_type\",
        \"ip_addresses\": [$(echo $ip_addresses | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')]
    }]" $CONFIG_FILE > temp.json && mv temp.json $CONFIG_FILE

    if [ "$LANGUAGE" == "zh" ]; then
        echo "域名添加成功!"
    else
        echo "Domain added successfully!"
    fi
}

function configure_language {
    echo "Choose your language / 选择您的语言:"
    echo "1) English"
    echo "2) 中文"

    read language_choice

    case $language_choice in
        1) LANGUAGE="en"; echo "Language set to English" ;;
        2) LANGUAGE="zh"; echo "语言设置为中文" ;;
        *) LANGUAGE="en"; echo "Invalid choice, defaulting to English." ;;
    esac
}

function create_python_script {
    if [ "$LANGUAGE" == "zh" ]; then
        echo "正在创建 Python 脚本..."
    else
        echo "Creating Python script..."
    fi

    cat << EOF > $PYTHON_SCRIPT
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
            config = json.load(config_file)

        # Validate Cloudflare config
        if 'cloudflare' not in config:
            logger.error("Missing 'cloudflare' configuration.")
            sys.exit(1)
        if 'api_key' not in config['cloudflare'] or 'email' not in config['cloudflare']:
            logger.error("Missing 'api_key' or 'email' in 'cloudflare' configuration.")
            sys.exit(1)

        # Validate Telegram config
        if 'telegram' not in config:
            logger.error("Missing 'telegram' configuration.")
            sys.exit(1)
        if 'bot_token' not in config['telegram'] or 'chat_id' not in config['telegram']:
            logger.error("Missing 'bot_token' or 'chat_id' in 'telegram' configuration.")
            sys.exit(1)

        # Validate records config
        if 'records' not in config or not config['records']:
            logger.error("No DNS records found in configuration.")
            sys.exit(1)

        # Validate health check config
        if 'health_check' not in config:
            logger.warning("Missing 'health_check' configuration, using defaults.")
            config['health_check'] = {}
        config['health_check'].setdefault('port', 80)
        config['health_check'].setdefault('timeout', 5)
        config['health_check'].setdefault('interval', 60)
        config['health_check'].setdefault('fail_threshold', 3)

        return config
    except Exception as e:
        logger.error("Failed to load configuration: {}".format(e))
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

# Send a Telegram notification
def send_telegram_notification(bot_token, chat_id, message, telegram_api_url=None):
    if telegram_api_url is None or not telegram_api_url:
        telegram_api_url = "https://api.telegram.org"
    
    # Log the URL being used
    logger.info("Using Telegram API URL: {}".format(telegram_api_url))

    url = "{}/bot{bot_token}/sendMessage".format(telegram_api_url.rstrip('/'), bot_token=bot_token)
    logger.info("Constructed URL: {}".format(url))

    params = {
        "chat_id": chat_id,
        "text": message
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        logger.info(f"Telegram notification sent successfully. Response: {response.text}")
    except requests.RequestException as e:
        logger.error(f"Failed to send Telegram notification: {e}")

# Main function to monitor DNS records
def main():
    config = load_config()
    auth = config['cloudflare']
    telegram_api_url = config['telegram'].get('api_url')

    # Log the loaded API URL
    logger.info(f"Using Telegram API URL: {telegram_api_url}")

    # Set up a counter to track consecutive health check failures
    fail_count = {record['name']: 0 for record in config['records']}
    fail_threshold = config['health_check'].get('fail_threshold', 3)  # Default threshold is 3 failures

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
                elif 'api_key' in auth and 'email' in auth':
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

                # Update DNS record immediately if the preferred IP is healthy and different from current
                if preferred_ip and preferred_ip != current_ip:
                    update_dns_record(zone_id, record, preferred_ip, auth)
                    send_telegram_notification(config['telegram']['bot_token'], config['telegram']['chat_id'], f"DNS record for {record['name']} updated to {preferred_ip}", telegram_api_url)
                    fail_count[record['name']] = 0  # Reset fail count after successful update
                elif preferred_ip == current_ip:
                    logger.info(f"No update needed for {record['name']}. Current IP is the preferred one.")
                    fail_count[record['name']] = 0  # Reset fail count since current IP is preferred
                else:
                    fail_count[record['name']] += 1
                    if fail_count[record['name']] >= fail_threshold:
                        logger.warning(f"All health checks failed for {record['name']}. No DNS update performed.")
                    else:
                        logger.info(f"Fail threshold not yet reached for {record['name']}. Incrementing fail count.")
            
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
EOF

    if [ "$LANGUAGE" == "zh" ]; then
        echo "Python 脚本创建成功!"
    else
        echo "Python script created successfully!"
    fi
}

function show_menu {
    while true; do
        if [ "$LANGUAGE" == "zh" ]; then
            echo "DNS 监控设置菜单"
            echo "1) 创建配置"
            echo "2) 列出域名"
            echo "3) 修改域名"
            echo "4) 删除域名"
            echo "5) 添加域名"
            echo "6) 设置语言"
            echo "7) 退出"
            echo "请输入您的选择:"
        else
            echo "DNS Monitor Setup Menu"
            echo "1) Create Config"
            echo "2) List Domains"
            echo "3) Modify Domain"
            echo "4) Delete Domain"
            echo "5) Add Domain"
            echo "6) Configure Language"
            echo "7) Exit"
            echo "Enter your choice:"
        fi

        read choice

        case $choice in
            1) create_config && create_python_script ;;
            2) list_domains ;;
            3) modify_domain ;;
            4) delete_domain ;;
            5) add_domain ;;
            6) configure_language ;;
            7) exit 0 ;;
            *) 
                if [ "$LANGUAGE" == "zh" ]; then
                    echo "无效的选项，请重试。"
                else
                    echo "Invalid option, please try again."
                fi
                ;;
        esac
    done
}

function install_dependencies {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -x "$(command -v apt-get)" ]; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip jq supervisor
        elif [ -x "$(command -v yum)" ]; then
            sudo yum install -y epel-release
            sudo yum install -y python3 python3-pip jq supervisor
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install python3 jq
    fi
}

function main {
    install_dependencies
    show_menu
}

main
