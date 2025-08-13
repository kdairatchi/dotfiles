#!/bin/bash
# secure_comms_installer.sh
# All-in-One Secure Communications Installer

set -e

print_status() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_status "Starting Secure Communications Suite Installation"

# Wait for APT lock to be free
print_status "Waiting for APT lock to be released..."
while sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    sleep 3
done

# Signal Desktop
print_status "Installing Signal Desktop..."
curl -fsSL https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor | sudo tee /usr/share/keyrings/signal-desktop-keyring.gpg > /dev/null
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] https://updates.signal.org/desktop/apt xenial main' | sudo tee /etc/apt/sources.list.d/signal-xenial.list
sudo apt update && sudo apt install -y signal-desktop

# Element (Matrix client)
print_status "Installing Element Matrix client..."
sudo curl -fsSL -o /usr/share/keyrings/element-io-archive-keyring.gpg https://packages.element.io/debian/element-io-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/element-io-archive-keyring.gpg] https://packages.element.io/debian/ default main" | sudo tee /etc/apt/sources.list.d/element-io.list
sudo apt update && sudo apt install -y element-desktop

# ProtonMail Bridge Dependencies
print_status "Installing ProtonMail Bridge dependencies..."
sudo apt install -y pass gnupg2

# Hardened GPG config
print_status "Setting up GPG with hardened configuration..."
mkdir -p ~/.gnupg && chmod 700 ~/.gnupg
cat > ~/.gnupg/gpg.conf << 'GPGEOF'
cert-digest-algo SHA512
cipher-algo AES256
digest-algo SHA512
compress-algo 2
s2k-digest-algo SHA512
s2k-cipher-algo AES256
s2k-count 65536
no-emit-version
no-comments
armor
GPGEOF

print_status "All tools installed and GPG configured."
print_status "Installed: Signal Desktop, Element Matrix, GPG hardened."
echo -e "\n\033[1;34m[!] You can now use these tools for secure comms in your bug bounty ops.\033[0m"

exit 0
