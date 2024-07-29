#!/bin/bash

set -eo pipefail

# root user is needed
if [[ $EUID -ne 0 ]]; then
    log "This script must be run as root or with sudo privileges"
    exit 1
fi

###############################################################
# HELPER FUNCTIONS

usage() {
    echo "Usage: $0 --backup-location <path> --plan-name <plan_name>"
    exit 1
}

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

handle_error() {
    log "Error occurred in function '$1' on line $2"
    exit 1
}

trap 'handle_error "${FUNCNAME[-1]}" "$LINENO"' ERR

install_dependencies() {
    log "Installing dependencies..."
    if [ -f /etc/debian_version ]; then
        apt-get update && sudo apt-get install -y tar unzip jq mysql-client wget curl
    elif [ -f /etc/redhat-release ]; then
        yum install -y epel-release tar unzip jq mysql wget curl
    elif [ -f /etc/almalinux-release ]; then
        dnf install -y tar unzip jq mysql wget curl
    else
        log "Unsupported OS. Please install tar, unzip, jq, mysql-client, wget, and curl manually."
        exit 1
    fi
    log "Dependencies installed successfully."
}

###############################################################
# MAIN FUNCTIONS

check_if_valid_cp_backup(){
    local backup_location="$1"
    local backup_filename=$(basename "$backup_location")
    local extraction_command=""

    case "$backup_filename" in
        cpmove-*.tar.gz | backup-*.tar.gz | *.tar.gz | *.tgz | *.tar)
            log "Identified valid cPanel backup format: $backup_filename"
            extraction_command="tar -xzf"
            ;;
        *.zip)
            log "Identified zip backup format: $backup_filename"
            extraction_command="unzip"
            ;;
        *)
            log "Unrecognized backup format: $backup_filename"
            exit 1
            ;;
    esac
}

# Extract
extract_cpanel_backup() {
    local backup_location="$1"
    local backup_dir="$2"
    log "Identifying and extracting backup from $backup_location to $backup_dir"
    mkdir -p "$backup_dir"

    # Extract the backup
    if [ "$extraction_command" = "unzip" ]; then
        $extraction_command "$backup_location" -d "$backup_dir"
    else
        $extraction_command "$backup_location" -C "$backup_dir"
    fi

    log "Backup extracted successfully."

    # Handle nested archives (common in some cPanel backups)
    for nested_archive in "$backup_dir"/*.tar.gz "$backup_dir"/*.tgz; do
        if [ -f "$nested_archive" ]; then
            log "Found nested archive: $nested_archive"
            tar -xzf "$nested_archive" -C "$backup_dir"
            rm "$nested_archive"  # Remove the nested archive after extraction
        fi
    done

    # List contents of extracted backup for debugging
    log "Contents of extracted backup:"
    find "$backup_dir" -type f | sed 's/^/  /'
}

# Function to locate important directories in the extracted backup
locate_backup_directories() {
    local backup_dir="$1"
    log "Locating important directories in the extracted backup"

    # Try to locate the key directories
    homedir=$(find "$backup_dir" -type d -name "homedir" | head -n 1)
    if [ -z "$homedir" ]; then
        homedir=$(find "$backup_dir" -type d -name "public_html" -printf '%h\n' | head -n 1)
    fi
    if [ -z "$homedir" ]; then
        log "Unable to locate home directory in the backup"
        exit 1
    fi

    mysqldir=$(find "$backup_dir" -type d -name "mysql" | head -n 1)
    if [ -z "$mysqldir" ]; then
        log "Unable to locate MySQL directory in the backup"
        exit 1
    fi

    log "Backup directories located successfully"
    log "Home directory: $homedir"
    log "MySQL directory: $mysqldir"
}

# Function to parse cPanel backup metadata
parse_cpanel_metadata() {
    local backup_dir="$1"
    log "Parsing cPanel metadata..."

    local metadata_file="$backup_dir/userdata/main"
    if [ ! -f "$metadata_file" ]; then
        metadata_file="$backup_dir/meta/user.yaml"
    fi

    if [ -f "$metadata_file" ]; then
        log "Metadata file found: $metadata_file"
        cpanel_email=$(grep -oP 'email: \K\S+' "$metadata_file" | tr -d '\r')
        main_domain=$(grep -oP 'main_domain: \K\S+' "$metadata_file" | tr -d '\r')
        php_version=$(grep -oP 'phpversion: \K\S+' "$metadata_file" | tr -d '\r')
        
        if [ -z "$php_version" ]; then
            php_version=$(grep -oP 'php_version: \K\S+' "$metadata_file" | tr -d '\r')
        fi
    fi

    # If metadata file doesn't exist or some information is missing, use backup file name and prompt for other details
    [ -z "$cpanel_email" ] && read -p "Enter cPanel email: " cpanel_email
    [ -z "$main_domain" ] && read -p "Enter main domain: " main_domain
    [ -z "$php_version" ] && read -p "Enter PHP version (e.g., php8.1): " php_version

    log "cPanel metadata parsed successfully."
    log "Email: $cpanel_email"
    log "Main Domain: $main_domain"
    log "PHP Version: $php_version"
}

check_if_user_exists(){   
    cpanel_username="${backup_filename##*_}"
    cpanel_username="${username%%.*}"
    log "Username: $cpanel_username"
    
    local existing_user=""
    if opencli user-list --json > /dev/null 2>&1; then
        existing_user=$(opencli user-list --json | jq -r ".[] | select(.username == \"$cpanel_username\") | .id")
    fi
    if [ -z "$existing_user" ]; then
        log "Username $cpanel_username is available, starting import.."
    else
        log "FATAL ERROR: $cpanel_username already exists."
        exit 1
    fi
}

# Function to create or get user
create_new_user() {
    local username="$1"
    local password="$2"
    local email="$3"
    local plan_name="$4"

    if ! opencli user-add "$username" "$password" "$email" "$plan_name"; then
        log "FATAL ERROR: Failed to create user. User might already exist or there might be an issue with the plan."
        #todo: show output from opencli command so we get the error
        exit 1
    fi
}

# Function to restore PHP version
restore_php_version() {
    local username="$1"
    local php_version="$2"

    log "Restoring PHP version $php_version for user $username"
    local current_version=$(opencli php-default_php_version "$username")
    if [ "$current_version" != "$php_version" ]; then
        local installed_versions=$(opencli php-enabled_php_versions "$username")
        if ! echo "$installed_versions" | grep -q "$php_version"; then
            opencli php-install_php_version "$username" "$php_version"
        fi
        opencli php-enabled_php_versions --update "$username" "$php_version"
    fi
}

# Function to restore domains
restore_domains() {
    local username="$1"
    local domain="$2"
    local path="$3"

    log "Restoring domain $domain for user $username"
    local domain_owner=$(opencli domains-whoowns "$domain")
    if [ -z "$domain_owner" ]; then
        opencli domains-add "$domain" "$username"
    else
        log "Domain $domain already exists and is owned by $domain_owner"
    fi
}

# Function to restore MySQL databases and users
restore_mysql() {
    local username="$1"
    local password="$2"
    local mysql_dir="$3"

    log "Restoring MySQL databases for user $username"
    if [ -d "$mysql_dir" ]; then
        for db_file in "$mysql_dir"/*.sql; do
            local db_name=$(basename "$db_file" .sql)
            log "Restoring database: $db_name"
            opencli db create "$db_name" "$username" "$password"
            #todo:
            #docker cp
            #docker exec
            mysql -u "$username" -p"$password" "$db_name" < "$db_file"
        done
    else
        log "No MySQL databases found to restore"
    fi
}

# Function to restore SSL certificates
restore_ssl() {
    local username="$1"
    local backup_dir="$2"

    log "Restoring SSL certificates for user $username"
    if [ -d "$backup_dir/ssl" ]; then
        for cert_file in "$backup_dir/ssl"/*.crt; do
            local domain=$(basename "$cert_file" .crt)
            local key_file="$backup_dir/ssl/$domain.key"
            if [ -f "$key_file" ]; then
                log "Installing SSL certificate for domain: $domain"
                opencli ssl install --domain "$domain" --cert "$cert_file" --key "$key_file"
            else
                log "SSL key file not found for domain: $domain"
            fi
        done
    else
        log "No SSL certificates found to restore"
    fi
}

# Function to restore SSH access
restore_ssh() {
    local username="$1"
    local backup_dir="$2"

    log "Restoring SSH access for user $username"
    local shell_access=$(grep -oP 'shell: \K\S+' "$backup_dir/userdata/main")
    if [ "$shell_access" == "/bin/bash" ]; then
        opencli user-ssh enable "$username"
        if [ -f "$backup_dir/.ssh/id_rsa.pub" ]; then
            mkdir -p "/home/$username/.ssh"
            cp "$backup_dir/.ssh/id_rsa.pub" "/home/$username/.ssh/authorized_keys"
            chown -R "$username:$username" "/home/$username/.ssh"
        fi
    fi
}

# Function to restore DNS zones
restore_dns_zones() {
    local username="$1"
    local backup_dir="$2"

    log "Restoring DNS zones for user $username"
    if [ -d "$backup_dir/dnszones" ]; then
        for zone_file in "$backup_dir/dnszones"/*; do
            local zone_name=$(basename "$zone_file")
            log "Importing DNS zone: $zone_name"
            opencli dns-import-zone "$zone_file"
        done
    else
        log "No DNS zones found to restore"
    fi
}

# Function to restore files
restore_files() {
    local backup_dir="$1"
    local username="$2"

    log "Restoring files for user $username to /home/$username/"
    cp -r "$backup_dir/homedir" "/home/$username/"
    opencli files-fix_permissions "$username"
}

# Function to restore WordPress sites
restore_wordpress() {
    local backup_dir="$1"
    local username="$2"

    log "Restoring WordPress sites for user $username"
    if [ -d "$backup_dir/wptoolkit" ]; then
        for wp_file in "$backup_dir/wptoolkit"/*.json; do
            log "Importing WordPress site from: $wp_file"
            opencli wp-import "$username" "$wp_file"
        done
    else
        log "No WordPress data found to restore"
    fi
}

# Function to restore cron jobs
restore_cron() {
    local backup_dir="$1"
    local username="$2"

    log "Restoring cron jobs for user $username"
    if [ -f "$backup_dir/cron/crontab" ]; then
        crontab -u "$username" "$backup_dir/cron/crontab"
    else
        log "No cron jobs found to restore"
    fi
}

###############################################################
# Main execution
main() {
    local backup_location=""
    local plan_name=""

    # Parse command-line arguments
    while [ "$1" != "" ]; do
        case $1 in
            --backup-location ) shift
                                backup_location=$1
                                ;;
            --plan-name )       shift
                                plan_name=$1
                                ;;
            * )                 usage
        esac
        shift
    done

    # Validate required parameters
    if [ -z "$backup_location" ] || [ -z "$plan_name" ]; then
        usage
    fi

    ################# PRE-RUN CHECKS
    check_if_valid_cp_backup "$backup_location"
    check_if_user_exists
    install_dependencies
    validate_plan_exists "$plan_name"

    # Create a unique temporary directory
    backup_dir=$(mktemp -d /tmp/cpanel_import_XXXXXX)
    log "Created temporary directory: $backup_dir"

    ################# RUN PROCESS
    # Extract backup
    extract_cpanel_backup "$backup_location" "$backup_dir"

    # Locate important directories
    locate_backup_directories "$backup_dir"

    # Parse cPanel metadata
    parse_cpanel_metadata "$backup_dir"

    # Create user
    create_new_user "$cpanel_username" "$cpanel_password" "$cpanel_email" "$plan_name"

    # Restore PHP version
    restore_php_version "$cpanel_username" "$php_version"

    # Restore main domain
    if [ -d "$homedir/public_html" ]; then
        restore_website "$main_domain" "$homedir/public_html"
    fi

    # Restore addon domains and subdomains
    if [ -d "$backup_dir/userdata" ]; then
        for domain_file in "$backup_dir/userdata"/*.yaml; do
            domain=$(basename "$domain_file" .yaml)
            domain_path=$(grep -oP 'documentroot: \K\S+' "$domain_file")
            restore_website "$domain" "$domain_path"
        done

        for subdomain_file in "$backup_dir/userdata"/*_subdomains.yaml; do
            subdomain=$(basename "$subdomain_file" _subdomains.yaml)
            subdomain_path=$(grep -oP 'documentroot: \K\S+' "$subdomain_file")
            full_subdomain="$subdomain.$main_domain"
            restore_website "$full_subdomain" "$subdomain_path"
        done
    fi

    # Restore other components
    restore_mysql "$cpanel_username" "$cpanel_password" "$mysqldir"
    restore_ssl "$cpanel_username" "$backup_dir"
    restore_ssh "$cpanel_username" "$backup_dir"
    restore_dns_zones "$cpanel_username" "$backup_dir"
    restore_files "$backup_dir" "$cpanel_username" "$main_domain"
    restore_wordpress "$backup_dir" "$cpanel_username"
    restore_cron "$backup_dir" "$cpanel_username"

    # Fix file permissions for the entire home directory
    log "Fixing file permissions for user $cpanel_username"
    opencli files-fix_permissions "$cpanel_username" "/home/$cpanel_username"

    ################# POST-RUN CHECKS
    # Add any additional post-run checks here if necessary

    # Cleanup
    log "Cleaning up temporary files"
    rm -rf "$backup_dir"

    log "Restore completed successfully."
}

###############################################################
# Run the main function
main "$@"
