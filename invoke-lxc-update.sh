#!/bin/bash

# PVE LXC Container Update Script
# This script updates all LXC containers on a Proxmox VE host
# Based on Debian unattended-upgrades best practices

set -euo pipefail

# Configuration
LOG_FILE="/var/log/lxc-updates.log"
BACKUP_DIR="/var/backups/lxc-updates"
MAX_CONCURRENT_UPDATES=3
DRY_RUN=false
FORCE_REBOOT=false
VERBOSE=false
SKIP_CONTAINERS=()  # Add container IDs to skip, e.g., (100 101)

# Global variables for summary (using regular arrays for compatibility)
CONTAINER_SUMMARY_FILE="/tmp/lxc-update-summary-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}"
}

# Summary data management functions
init_summary() {
    > "$CONTAINER_SUMMARY_FILE"
}

set_summary() {
    local container_id=$1
    local key=$2
    local value=$3
    echo "${container_id}:${key}:${value}" >> "$CONTAINER_SUMMARY_FILE"
}

get_summary() {
    local container_id=$1
    local key=$2
    grep "^${container_id}:${key}:" "$CONTAINER_SUMMARY_FILE" 2>/dev/null | cut -d: -f3- || echo ""
}

cleanup_summary() {
    rm -f "$CONTAINER_SUMMARY_FILE"
}

# Error handling
error_exit() {
    log "ERROR" "${RED}$1${NC}"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Check if PVE tools are available
check_pve_tools() {
    if ! command -v pct &> /dev/null; then
        error_exit "PVE tools (pct) not found. Are you running this on a PVE host?"
    fi
}

# Get list of running LXC containers
get_running_containers() {
    pct list | awk '$2 == "running" {print $1}' | sort -n
}

# Check if container should be skipped
should_skip_container() {
    local container_id=$1
    for skip_id in "${SKIP_CONTAINERS[@]}"; do
        if [[ "$container_id" == "$skip_id" ]]; then
            return 0
        fi
    done
    return 1
}

# Get container info
get_container_info() {
    local container_id=$1
    local hostname=$(pct config "$container_id" | grep -E '^hostname:' | awk '{print $2}' || echo "unknown")
    local os=$(pct config "$container_id" | grep -E '^ostype:' | awk '{print $2}' || echo "unknown")
    echo "${hostname} (${os})"
}

# Update a single container
update_container() {
    local container_id=$1
    local container_info=$(get_container_info "$container_id")
    local start_time=$(date +%s)
    
    log "INFO" "${BLUE}Starting update for container ${container_id}: ${container_info}${NC}"
    
    # Create backup directory for this container
    local container_backup_dir="${BACKUP_DIR}/container-${container_id}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$container_backup_dir"
    
    # Determine update command based on OS
    local update_cmd
    local os=$(pct config "$container_id" | grep -E '^ostype:' | awk '{print $2}')
    
    case "$os" in
        "debian"|"ubuntu")
            update_cmd="apt update && apt upgrade -y && apt autoremove -y && apt autoclean"
            ;;
        "centos"|"rhel"|"almalinux"|"rocky")
            update_cmd="yum update -y && yum clean all"
            ;;
        "fedora")
            update_cmd="dnf update -y && dnf clean all"
            ;;
        "alpine")
            update_cmd="apk update && apk upgrade"
            ;;
        "archlinux")
            update_cmd="pacman -Syu --noconfirm"
            ;;
        *)
            log "WARNING" "${YELLOW}Unknown OS type '${os}' for container ${container_id}, using generic update${NC}"
            update_cmd="apt update && apt upgrade -y || yum update -y || dnf update -y || apk update && apk upgrade"
            ;;
    esac
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "${YELLOW}[DRY RUN] Would execute: ${update_cmd}${NC}"
        return 0
    fi
    
    # Execute update with verbose output if requested
    local update_output
    local update_success=false
    local packages_updated=0
    local packages_removed=0
    
    if [[ "$VERBOSE" == "true" ]]; then
        log "INFO" "${BLUE}Executing update command with verbose output...${NC}"
        
        # Run update with real-time output
        if pct exec "$container_id" -- bash -c "$update_cmd" 2>&1 | while IFS= read -r line; do
            echo -e "${BLUE}[${container_id}]${NC} $line"
            echo "$line" >> "${container_backup_dir}/update.log"
        done; then
            update_success=true
        fi
    else
        # Standard execution
        if update_output=$(pct exec "$container_id" -- bash -c "$update_cmd" 2>&1); then
            update_success=true
            echo "$update_output" > "${container_backup_dir}/update.log"
        else
            echo "$update_output" > "${container_backup_dir}/update-error.log"
        fi
    fi
    
    # Calculate update time
    local end_time=$(date +%s)
    local update_duration=$((end_time - start_time))
    
    if [[ "$update_success" == "true" ]]; then
        log "INFO" "${GREEN}Successfully updated container ${container_id} in ${update_duration}s${NC}"
        
        # Parse package counts from update output
        if [[ "$VERBOSE" != "true" && -n "${update_output:-}" ]]; then
            packages_updated=$(echo "$update_output" | grep -E "(upgraded|installed|removed)" | awk '{sum += $1} END {print sum+0}')
            packages_removed=$(echo "$update_output" | grep -E "autoremove" | awk '{print $1+0}')
        fi
        
        # Store summary information
        set_summary "$container_id" "status" "SUCCESS"
        set_summary "$container_id" "packages" "$packages_updated"
        set_summary "$container_id" "removed" "$packages_removed"
        set_summary "$container_id" "duration" "$update_duration"
        set_summary "$container_id" "info" "$container_info"
        
        # Check if reboot is needed
        local reboot_needed=false
        local update_content="${update_output:-}"
        if [[ "$VERBOSE" == "true" ]]; then
            update_content=$(cat "${container_backup_dir}/update.log" 2>/dev/null || echo "")
        fi
        
        if echo "$update_content" | grep -qi "reboot\|restart\|kernel"; then
            reboot_needed=true
        fi
        
        # Handle reboot
        if [[ "$reboot_needed" == "true" || "$FORCE_REBOOT" == "true" ]]; then
            log "INFO" "${YELLOW}Rebooting container ${container_id}...${NC}"
            pct reboot "$container_id"
            
            # Wait for container to come back up
            local max_wait=300  # 5 minutes
            local wait_time=0
            while [[ $wait_time -lt $max_wait ]]; do
                if pct status "$container_id" | grep -q "running"; then
                    log "INFO" "${GREEN}Container ${container_id} is back online${NC}"
                    set_summary "$container_id" "rebooted" "YES"
                    break
                fi
                sleep 10
                wait_time=$((wait_time + 10))
            done
            
            if [[ $wait_time -ge $max_wait ]]; then
                log "ERROR" "${RED}Container ${container_id} failed to come back online within ${max_wait} seconds${NC}"
                set_summary "$container_id" "status" "REBOOT_FAILED"
                return 1
            fi
        else
            set_summary "$container_id" "rebooted" "NO"
        fi
        
        return 0
    else
        log "ERROR" "${RED}Failed to update container ${container_id}${NC}"
        set_summary "$container_id" "status" "FAILED"
        set_summary "$container_id" "info" "$container_info"
        set_summary "$container_id" "duration" "$update_duration"
        return 1
    fi
}

# Display comprehensive summary
display_summary() {
    local successful_containers=("$@")
    local failed_containers=()
    
    # Separate successful and failed containers
    local in_failed=false
    for container in "$@"; do
        if [[ "$container" == "FAILED_START" ]]; then
            in_failed=true
            continue
        fi
        if [[ "$in_failed" == "true" ]]; then
            failed_containers+=("$container")
        fi
    done
    
    # Remove the separator from successful containers
    local clean_successful=()
    for container in "${successful_containers[@]}"; do
        if [[ "$container" != "FAILED_START" ]]; then
            clean_successful+=("$container")
        fi
    done
    
    echo
    log "INFO" "${BLUE}========================================${NC}"
    log "INFO" "${BLUE}        UPDATE SUMMARY REPORT${NC}"
    log "INFO" "${BLUE}========================================${NC}"
    echo
    
    # Overall statistics
    local total_containers=$((${#clean_successful[@]} + ${#failed_containers[@]}))
    local total_packages=0
    local total_removed=0
    local total_time=0
    local rebooted_count=0
    
    log "INFO" "${GREEN}Overall Statistics:${NC}"
    log "INFO" "  Total containers processed: $total_containers"
    log "INFO" "  Successful updates: ${#clean_successful[@]}"
    log "INFO" "  Failed updates: ${#failed_containers[@]}"
    echo
    
    # Detailed container information
    if [[ ${#clean_successful[@]} -gt 0 ]]; then
        log "INFO" "${GREEN}Successful Updates:${NC}"
        printf "%-8s %-20s %-12s %-8s %-8s %-8s %-10s\n" "ID" "Hostname (OS)" "Status" "Pkgs" "Removed" "Time(s)" "Rebooted"
        printf "%-8s %-20s %-12s %-8s %-8s %-8s %-10s\n" "----" "--------------------" "------------" "--------" "--------" "--------" "----------"
        
        for container_id in "${clean_successful[@]}"; do
            local info=$(get_summary "$container_id" "info")
            local status=$(get_summary "$container_id" "status")
            local packages=$(get_summary "$container_id" "packages")
            local removed=$(get_summary "$container_id" "removed")
            local duration=$(get_summary "$container_id" "duration")
            local rebooted=$(get_summary "$container_id" "rebooted")
            
            # Set defaults if empty
            packages=${packages:-0}
            removed=${removed:-0}
            duration=${duration:-0}
            rebooted=${rebooted:-NO}
            
            # Truncate long hostnames
            local short_info="$info"
            if [[ ${#info} -gt 20 ]]; then
                short_info="${info:0:17}..."
            fi
            
            printf "%-8s %-20s %-12s %-8s %-8s %-8s %-10s\n" \
                "$container_id" "$short_info" "$status" "$packages" "$removed" "$duration" "$rebooted"
            
            total_packages=$((total_packages + packages))
            total_removed=$((total_removed + removed))
            total_time=$((total_time + duration))
            
            if [[ "$rebooted" == "YES" ]]; then
                rebooted_count=$((rebooted_count + 1))
            fi
        done
        echo
    fi
    
    if [[ ${#failed_containers[@]} -gt 0 ]]; then
        log "INFO" "${RED}Failed Updates:${NC}"
        printf "%-8s %-20s %-12s %-8s\n" "ID" "Hostname (OS)" "Status" "Time(s)"
        printf "%-8s %-20s %-12s %-8s\n" "----" "--------------------" "------------" "--------"
        
        for container_id in "${failed_containers[@]}"; do
            local info=$(get_summary "$container_id" "info")
            local status=$(get_summary "$container_id" "status")
            local duration=$(get_summary "$container_id" "duration")
            duration=${duration:-0}
            
            # Truncate long hostnames
            local short_info="$info"
            if [[ ${#info} -gt 20 ]]; then
                short_info="${info:0:17}..."
            fi
            
            printf "%-8s %-20s %-12s %-8s\n" \
                "$container_id" "$short_info" "$status" "$duration"
        done
        echo
    fi
    
    # Summary statistics
    log "INFO" "${BLUE}Summary Statistics:${NC}"
    log "INFO" "  Total packages updated: $total_packages"
    log "INFO" "  Total packages removed: $total_removed"
    log "INFO" "  Total update time: ${total_time}s"
    log "INFO" "  Average time per container: $((total_containers > 0 ? total_time / total_containers : 0))s"
    log "INFO" "  Containers rebooted: $rebooted_count"
    echo
    
    # Log file information
    log "INFO" "${BLUE}Log Files:${NC}"
    log "INFO" "  Main log: $LOG_FILE"
    log "INFO" "  Backup directory: $BACKUP_DIR"
    echo
    
    # Final status
    if [[ ${#failed_containers[@]} -eq 0 ]]; then
        log "INFO" "${GREEN}✓ All container updates completed successfully!${NC}"
    else
        log "ERROR" "${RED}✗ Some container updates failed. Check logs for details.${NC}"
    fi
    
    log "INFO" "${BLUE}========================================${NC}"
    echo
}

# Main update function
main() {
    log "INFO" "${BLUE}Starting LXC container update process${NC}"
    
    # Initialize summary tracking
    init_summary
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Get list of running containers
    local containers=($(get_running_containers))
    
    if [[ ${#containers[@]} -eq 0 ]]; then
        log "WARNING" "${YELLOW}No running LXC containers found${NC}"
        return 0
    fi
    
    log "INFO" "Found ${#containers[@]} running containers: ${containers[*]}"
    
    # Process containers
    local failed_containers=()
    local successful_containers=()
    
    for container_id in "${containers[@]}"; do
        if should_skip_container "$container_id"; then
            log "INFO" "${YELLOW}Skipping container ${container_id} (in skip list)${NC}"
            continue
        fi
        
        if update_container "$container_id"; then
            successful_containers+=("$container_id")
        else
            failed_containers+=("$container_id")
        fi
        
        # Add delay between containers to avoid overwhelming the system
        sleep 5
    done
    
    # Display comprehensive summary
    display_summary "${successful_containers[@]}" "FAILED_START" "${failed_containers[@]}"
    
    # Cleanup summary file
    cleanup_summary
    
    if [[ ${#failed_containers[@]} -gt 0 ]]; then
        return 1
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force-reboot)
                FORCE_REBOOT=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --skip=*)
                IFS=',' read -ra SKIP_CONTAINERS <<< "${1#*=}"
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --dry-run        Show what would be done without executing"
                echo "  --force-reboot   Force reboot all containers after update"
                echo "  --verbose        Show detailed package update output in real-time"
                echo "  --skip=ID1,ID2   Skip specific container IDs"
                echo "  --help           Show this help message"
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_args "$@"
    check_root
    check_pve_tools
    main
fi
