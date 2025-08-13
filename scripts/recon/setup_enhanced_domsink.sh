#!/bin/bash

echo "[*] Setting up Enhanced DOM Sink Scanner Framework"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "[-] Python 3 is required but not installed"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "[-] pip3 is required but not installed"
    exit 1
fi

echo "[+] Installing Python dependencies..."

# Install required packages
pip3 install playwright beautifulsoup4 aiohttp tqdm pyyaml

echo "[+] Installing Playwright browsers..."
python3 -m playwright install chromium

# Create necessary directories
echo "[+] Creating output directories..."
mkdir -p nuclei_templates
mkdir -p poc_screenshots
mkdir -p scan_results

# Make scripts executable
echo "[+] Setting script permissions..."
chmod +x enhanced_domsink_scanner.py
chmod +x playwright_dom_poc_framework.py  
chmod +x comprehensive_dom_scanner.py

echo "[+] Setup complete!"
echo ""
echo "Usage Examples:"
echo "  # Basic DOM sink scanning"
echo "  ./enhanced_domsink_scanner.py urls.txt"
echo ""
echo "  # PoC framework testing"
echo "  ./playwright_dom_poc_framework.py https://example.com --sinks innerHTML document.write setAttribute"
echo ""
echo "  # Comprehensive scanning (recommended)"
echo "  ./comprehensive_dom_scanner.py urls.txt -o results.json"
echo ""
echo "Configuration:"
echo "  Edit domsink_config.yaml to customize scanning behavior"
echo ""
echo "Output Directories:"
echo "  - nuclei_templates/     : Generated Nuclei templates"
echo "  - poc_screenshots/      : PoC execution screenshots"
echo "  - scan_results/         : Detailed scan results"