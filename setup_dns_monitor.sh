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
    apt-get install -y python3 python3-pip supervisor nginx
elif command -v yum >/dev/null 2>&1; then
    echo "Installing necessary packages using yum..."
    yum install -y epel-release
    yum install -y python3 python3-pip supervisor nginx
elif command -v dnf >/dev/null 2>&1; then
    echo "Installing necessary packages using dnf..."
    dnf install -y python3 python3-pip supervisor nginx
else
    echo "Unsupported package manager. Please install Python 3, pip, supervisor, and nginx manually."
    exit 1
fi

# Install required Python packages
pip3 install requests

# Prompt the user for Cloudflare and Telegram details
CLOUDFLARE_API_KEY=$(prompt_for_input "Enter your Cloudflare API key" "")
CLOUDFLARE_EMAIL=$(prompt_for_input "Enter your Cloudflare email" "")
TELEGRAM_BOT_TOKEN=$(prompt_for_input "Enter your Telegram Bot API token" "")
TELEGRAM_CHAT_ID=$(prompt_for_input "Enter your Telegram Chat ID" "")

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
    "telegram": {
        "bot_token": "$TELEGRAM_BOT_TOKEN",
        "chat_id": "$TELEGRAM_CHAT_ID"
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
# Insert the entire content of the updated monitor_dns.py script here.
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

# Instructions for setting up Nginx as a reverse proxy for the Telegram API
echo "If you are using a Chinese server and are facing issues connecting to the Telegram API, consider setting up an Nginx reverse proxy."
echo "Here is a sample Nginx configuration to use as a reverse proxy for Telegram Bot API:"
echo "
## Telegram API Reverse Proxy
server {
    listen 80;
    listen [::]:80;
    server_name telegram.example.com;

    # Enforce HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name telegram.example.com;

    ## Update with your SSL certificate paths
    ssl_certificate /etc/nginx/cert/full_chain.pem;
    ssl_certificate_key /etc/nginx/cert/private.key;

    ## DNS resolver
    resolver 8.8.8.8;

    # Forward bot requests to Telegram API
    location ~* ^/bot {
        proxy_buffering off;
        proxy_pass https://api.telegram.org\$request_uri;
        proxy_http_version 1.1;
    }

    # Optional: You can use this to check server status, or disable it with return 403;
    location / {
        try_files \$uri \$uri /index.html;
    }
}

Remember to update the 'server_name' and SSL certificate paths. After editing, reload Nginx with:
    sudo nginx -s reload

Test your setup with:
    curl https://telegram.example.com/bot[Your Bot Token]/getMe
If you get a JSON response, the setup is successful.
"
