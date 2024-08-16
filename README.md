### README

# DNS Monitoring Service with Cloudflare API and Telegram Notifications

This repository provides a DNS monitoring service that checks the health of multiple IP addresses and dynamically updates DNS records using the Cloudflare API. The service also sends notifications via Telegram whenever a DNS record is updated.

## Features

- **Automatic DNS Failover**: Monitors multiple IP addresses and updates DNS records if a primary IP becomes unavailable.
- **Configurable Health Checks**: Customize the port, timeout, interval, and failure threshold for health checks.
- **Telegram Notifications**: Receive real-time notifications via Telegram when DNS records are updated.
- **Cross-Platform Support**: Works on all major Linux distributions (Ubuntu, Debian, CentOS, RHEL, Fedora).

## Prerequisites

- A server running a supported Linux distribution (Ubuntu, Debian, CentOS, RHEL, Fedora).
- Python 3 installed on the server.
- `supervisord` and `nginx` installed on the server.
- Cloudflare account with an API key and email.
- Telegram bot token and chat ID.

## Installation

### Run the Installer Script:

```bash
bash <(curl -L -s https://raw.githubusercontent.com/zytakeshi/CloudflareDnsFailoverForVpns/main/setup_dns_monitor.sh)
```

### Follow the Prompts:

The installer will prompt you to enter:

- Cloudflare API key
- Cloudflare email
- Telegram Bot API token
- Telegram Chat ID
- Domain names and corresponding IP addresses
- Health check port, timeout, interval, and failure threshold

The installer will automatically create the necessary configuration files and set up `supervisord` to manage the DNS monitor service.

## Configuration

The `config.json` file is generated during the installation process. It contains the following sections:

- **Cloudflare Authentication**:

  ```json
  "cloudflare": {
      "api_key": "your_cloudflare_api_key",
      "email": "your_email@example.com"
  }
  ```

- **Telegram Settings**:

  ```json
  "telegram": {
      "bot_token": "your_telegram_bot_token",
      "chat_id": "your_chat_id"
  }
  ```

- **DNS Records**: Each domain you want to monitor is listed under the `records` section:

  ```json
  "records": [
      {
          "name": "example.com",
          "type": "A",
          "ip_addresses": ["192.0.2.1", "198.51.100.2"]
      }
 

 ]
  ```

- **Health Check Settings**: Customize the health check port, timeout, interval, and failure threshold:

  ```json
  "health_check": {
      "port": 14006,
      "timeout": 5,
      "interval": 60,
      "fail_threshold": 3
  }
  ```

## Managing the Service

The DNS monitor service is managed by `supervisord`. You can control the service using the following commands:

- **Check the Status**:

  ```bash
  sudo supervisorctl status dnsmonitor
  ```

- **Start the Service**:

  ```bash
  sudo supervisorctl start dnsmonitor
  ```

- **Stop the Service**:

  ```bash
  sudo supervisorctl stop dnsmonitor
  ```

- **Restart the Service**:

  ```bash
  sudo supervisorctl restart dnsmonitor
  ```

## Using a Reverse Proxy for Telegram API (Chinese Servers)

If you are using a server in China and facing issues connecting to the Telegram API, you can set up an Nginx reverse proxy to route requests to Telegram. This allows your bot to function correctly despite restrictions.

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

### Setting Up the Reverse Proxy

1. **Edit the Nginx Configuration**: Replace `telegram.example.com` with your domain and update the paths to your SSL certificates.

2. **Reload Nginx**:

   ```bash
   sudo nginx -s reload
   ```

3. **Test the Setup**:

   ```bash
   curl https://telegram.example.com/bot[Your Bot Token]/getMe
   ```

   If you receive a JSON response, your reverse proxy is working correctly.

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
```
