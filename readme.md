# 1) Put it on PATH
chmod +x net-opsec.sh && sudo mv net-opsec.sh /usr/local/bin/net-opsec

# 2) Quick checks
net-opsec --ip
net-opsec --tor
net-opsec --dns
net-opsec --proxychains-test

# 3) Optional: RedChains smoke
cd ~/dotfiles/s/security
net-opsec --redchains             # quick
net-opsec --redchains-full        # fetch+check (caps jobs)
