#!/bin/bash

CONFIG_FILE="config.json"

function create_config {
    echo "Creating new config.json..."
    echo "{}" > $CONFIG_FILE

    echo "Enter your Cloudflare API key:"
    read cloudflare_api_key

    echo "Enter your Cloudflare email:"
    read cloudflare_email

    echo "Enter your Telegram bot token (optional):"
    read telegram_bot_token

    echo "Enter your Telegram chat ID (optional):"
    read telegram_chat_id

    echo "Enter your custom Telegram API URL (optional):"
    read telegram_api_url

    echo "Enter the port to be monitored:"
    read health_check_port

    echo "Enter the timeout for health checks (in seconds):"
    read health_check_timeout

    echo "Enter the interval between health checks (in seconds):"
    read health_check_interval

    echo "Enter the fail threshold (number of failed checks before updating DNS):"
    read fail_threshold

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

    echo "Configuration created successfully!"
}

function list_domains {
    jq '.records[] | .name' $CONFIG_FILE
}

function modify_domain {
    echo "Enter the domain to modify:"
    read domain

    index=$(jq ".records | map(.name == \"$domain\") | index(true)" $CONFIG_FILE)

    if [ "$index" == "null" ]; then
        echo "Domain not found."
        return
    fi

    echo "Enter new IP addresses (comma-separated):"
    read new_ips

    jq ".records[$index].ip_addresses = [$(echo $new_ips | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')]" $CONFIG_FILE > temp.json && mv temp.json $CONFIG_FILE
    echo "Domain IP addresses updated successfully!"
}

function delete_domain {
    echo "Enter the domain to delete:"
    read domain

    jq ".records |= map(select(.name != \"$domain\"))" $CONFIG_FILE > temp.json && mv temp.json $CONFIG_FILE
    echo "Domain deleted successfully!"
}

function add_domain {
    echo "Enter the domain name:"
    read domain

    echo "Enter the record type (e.g., A, CNAME):"
    read record_type

    echo "Enter the IP addresses (comma-separated):"
    read ip_addresses

    jq ".records += [{
        \"name\": \"$domain\",
        \"type\": \"$record_type\",
        \"ip_addresses\": [$(echo $ip_addresses | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')]
    }]" $CONFIG_FILE > temp.json && mv temp.json $CONFIG_FILE

    echo "Domain added successfully!"
}

function configure_language {
    echo "Choose your language / 选择您的语言:"
    echo "1) English"
    echo "2) 中文"

    read language_choice

    case $language_choice in
        1) echo "Language set to English" ;;
        2) echo "语言设置为中文" ;;
        *) echo "Invalid choice, defaulting to English." ;;
    esac
}

function show_menu {
    while true; do
        echo "DNS Monitor Setup Menu"
        echo "1) Create Config"
        echo "2) List Domains"
        echo "3) Modify Domain"
        echo "4) Delete Domain"
        echo "5) Add Domain"
        echo "6) Configure Language"
        echo "7) Exit"
        echo "Enter your choice:"

        read choice

        case $choice in
            1) create_config ;;
            2) list_domains ;;
            3) modify_domain ;;
            4) delete_domain ;;
            5) add_domain ;;
            6) configure_language ;;
            7) exit 0 ;;
            *) echo "Invalid option, please try again." ;;
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
