### README

# DNS Monitoring Service with Cloudflare API and Telegram Notifications

This repository provides a DNS monitoring service that checks the health of multiple IP addresses and dynamically updates DNS records using the Cloudflare API. The service also sends notifications via Telegram whenever a DNS record is updated.

## Features
- **Automatic DNS Failover**: Monitors multiple IP addresses and updates DNS records if a primary IP becomes unavailable.
- **Configurable Health Checks**: Customize the port, timeout, and interval for health checks.
- **Telegram Notifications**: Receive real-time notifications via Telegram when DNS records are updated.
- **Multi-language Support**: Supports English and Chinese languages for configuration.
- **Interactive Menu**: Provides an interactive menu to manage configuration.

## Prerequisites
- A server running a supported Linux distribution (Ubuntu, Debian, CentOS, RHEL, Fedora).
- Python 3 installed on the server.
- `jq`, `supervisor`, and `nginx` installed on the server.
- Cloudflare account with an API key and email.
- Telegram bot token and chat ID.

## Installation

### Run the Installer Script
```bash
bash <(curl -L -s https://raw.githubusercontent.com/zytakeshi/CloudflareDnsFailoverForVpns/main/setup_dns_monitor.sh)
```

### Follow the Prompts
The installer will prompt you to enter:
- Cloudflare API key
- Cloudflare email
- Telegram Bot API token
- Telegram Chat ID
- Custom Telegram API URL
- Health check port, timeout, and interval
- Fail threshold

### Managing Configuration
Use the interactive menu to:
- List domains
- Modify domain IP addresses
- Delete domains
- Add new domains
- Configure the language

## Using a Reverse Proxy for Telegram API (Chinese Servers)
If you are using a server in China and facing issues connecting to the Telegram API, you can set up an Nginx reverse proxy to route requests to Telegram.

### Nginx Configuration Example
```nginx
## Telegram API Reverse Proxy
server {
    listen 80;
    listen [::]:80;
    server_name telegram.example.com;

    # Enforce HTTPS
    return 301 https://$server_name$request_uri;
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
        proxy_pass https://api.telegram.org$request_uri;
        proxy_http_version 1.1;
    }

    # Optional: You can use this to check server status, or disable it with return 403;
    location / {
        try_files $uri $uri /index.html;
    }
}
```

## Uninstallation
To stop and remove the DNS monitor service, follow these steps:

1. **Stop the Service**:
   ```bash
   sudo supervisorctl stop dnsmonitor
   ```

2. **Remove the Supervisor Configuration**:
   ```bash
   sudo rm /etc/supervisord.d/dnsmonitor.conf
   ```

3. **Reload Supervisor**:
   ```bash
   sudo supervisorctl reread
   sudo supervisorctl update
   ```

4. **Remove the DNS Monitor Files**:
   ```bash
   rm -rf /path/to/dns-monitor
   ```

## License
This project is licensed under the GNU 3.0 License.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or features you'd like to add.
