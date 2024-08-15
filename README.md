# DNS Monitoring Service with Cloudflare API

This repository provides a DNS monitoring service that checks the health of multiple IP addresses and dynamically updates DNS records using the Cloudflare API. The service is managed by `supervisord`, ensuring that it runs in the background and automatically restarts if necessary.

## Features

- **Automatic DNS Failover**: Monitors multiple IP addresses and updates DNS records if a primary IP becomes unavailable.
- **Configurable Health Checks**: Customize the port, timeout, and interval for health checks.
- **Easy Installation**: The installation script sets up everything, including the necessary Python environment and `supervisord` configuration.
- **Cross-Platform Support**: Works on all major Linux distributions (Ubuntu, Debian, CentOS, RHEL, Fedora).

## Prerequisites

- A server running a supported Linux distribution (Ubuntu, Debian, CentOS, RHEL, Fedora).
- Python 3 installed on the server.
- `supervisord` installed on the server.
- Cloudflare account with an API key and email.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/zytakeshi/CloudflareDnsFailoverForVpns.git
   ```

2. **Run the Installer Script**:

   Make the script executable and run it:

   ```bash
   chmod +x setup_dns_monitor.sh
   sudo ./setup_dns_monitor.sh
   ```

3. **Follow the Prompts**:

   The installer will prompt you to enter:
   - Cloudflare API key
   - Cloudflare email
   - Domain names and corresponding IP addresses
   - Health check port, timeout, and interval

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

- **DNS Records**:
  Each domain you want to monitor is listed under the `records` section:

  ```json
  "records": [
      {
          "name": "example.com",
          "type": "A",
          "ip_addresses": ["192.0.2.1", "198.51.100.2"]
      }
  ]
  ```

- **Health Check Settings**:
  Customize the health check port, timeout, and interval:

  ```json
  "health_check": {
      "port": 14006,
      "timeout": 5,
      "interval": 60
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

## Viewing Logs

Logs for the DNS monitor service are stored in the following locations:

- **Standard Output Log**:
  ```bash
  /var/log/dnsmonitor.out.log
  ```

- **Standard Error Log**:
  ```bash
  /var/log/dnsmonitor.err.log
  ```

You can view these logs in real-time using the `tail` command:

```bash
tail -f /var/log/dnsmonitor.out.log /var/log/dnsmonitor.err.log
```
Or check the status by entering
```bash
sudo supervisorctl status dnsmonitor
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

This project is licensed under the GNU3 License. 

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or features you'd like to add.
