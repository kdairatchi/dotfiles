#!/bin/bash

# Ultimate Bug Bounty Framework - Docker Entrypoint
# Optimized for high-performance parallel processing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
echo -e "${BLUE}=================================="
echo -e "Ultimate Bug Bounty Framework"
echo -e "High-Performance Security Scanner"
echo -e "Max Parallel Jobs: 9000"
echo -e "==================================${NC}"

# System optimization for containerized environment
echo -e "${YELLOW}Optimizing system for high-performance scanning...${NC}"

# Increase file descriptor limits
ulimit -n 65536 2>/dev/null || echo -e "${YELLOW}Warning: Could not increase FD limits${NC}"

# Set optimal parallel job count
export J=$(nproc 2>/dev/null || echo 4)
export J=$((J * 64))
if [[ $J -gt 9000 ]]; then
    export J=9000
fi

echo -e "${GREEN}✓ Optimal parallel jobs: $J${NC}"

# Verify core tools are available
echo -e "${YELLOW}Verifying security tools...${NC}"
tools=("nuclei" "subfinder" "httpx" "naabu" "ffuf" "waybackurls" "assetfinder" "gau" "dalfox")
missing_tools=()

for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ $tool${NC}"
    else
        echo -e "${RED}✗ $tool${NC}"
        missing_tools+=("$tool")
    fi
done

# Report missing tools
if [[ ${#missing_tools[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Warning: Missing tools: ${missing_tools[*]}${NC}"
    echo -e "${YELLOW}Run installation script to install missing tools${NC}"
fi

# Load security functions
if [[ -f "/home/kali/dotfiles/.security_aliases" ]]; then
    source /home/kali/dotfiles/.security_aliases
    echo -e "${GREEN}✓ Security functions loaded${NC}"
else
    echo -e "${YELLOW}Warning: Security aliases not found${NC}"
fi

# Check if Nuclei templates are up to date
echo -e "${YELLOW}Checking Nuclei templates...${NC}"
template_count=$(find ~/.nuclei-templates -name "*.yaml" 2>/dev/null | wc -l || echo 0)
if [[ $template_count -gt 1000 ]]; then
    echo -e "${GREEN}✓ Nuclei templates loaded ($template_count templates)${NC}"
else
    echo -e "${YELLOW}Warning: Few Nuclei templates found. Run 'nuclei -update-templates'${NC}"
fi

# Display usage information
echo -e "${BLUE}=== Usage Examples ===${NC}"
echo -e "${GREEN}Framework Scripts:${NC}"
echo "  ./dotfiles/scripts/recon/bug_bounty_framework/quick_scan.sh example.com"
echo "  ./dotfiles/scripts/recon/bug_bounty_framework/advanced_scan.sh example.com"
echo "  ./dotfiles/scripts/recon/bug_bounty_framework/ultimate_scan.sh -t comprehensive example.com"
echo ""
echo -e "${GREEN}Security Functions:${NC}"
echo "  quick_sub_enum example.com"
echo "  recon_pipeline example.com 5000"
echo "  bulk_nuclei_scan targets.txt"
echo ""
echo -e "${GREEN}Individual Tools:${NC}"
echo "  subfinder -d example.com -all -silent"
echo "  httpx -l subdomains.txt -threads 5000 -tech-detect"
echo "  nuclei -l targets.txt -severity critical,high -j 5000"

# Check if arguments were passed for direct execution
if [[ $# -gt 0 ]]; then
    # If it's a recognized script, run it directly
    case "$1" in
        "quick_scan"|"advanced_scan"|"ultimate_scan")
            script_path="/home/kali/dotfiles/scripts/recon/bug_bounty_framework/${1}.sh"
            if [[ -f "$script_path" ]]; then
                echo -e "${BLUE}Running $1 script...${NC}"
                shift
                exec "$script_path" "$@"
            else
                echo -e "${RED}Error: Script $script_path not found${NC}"
                exit 1
            fi
            ;;
        "recon_pipeline"|"quick_sub_enum"|"bulk_nuclei_scan")
            echo -e "${BLUE}Running $1 function...${NC}"
            source /home/kali/dotfiles/.security_aliases
            exec bash -c "$*"
            ;;
        *)
            # Execute whatever command was passed
            exec "$@"
            ;;
    esac
else
    # No arguments, start interactive shell
    echo -e "${BLUE}Starting interactive shell...${NC}"
    echo -e "${GREEN}Type 'exit' to quit${NC}"
    exec bash
fi