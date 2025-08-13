# Ultimate Bug Bounty Framework - Optimized Docker Container
FROM kalilinux/kali-rolling:latest

LABEL maintainer="Security Research Team"
LABEL description="High-performance bug bounty framework with 9000 parallel jobs support"
LABEL version="2.0"

# Set environment variables for optimal performance
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/home/kali/go
ENV PATH="${PATH}:/home/kali/go/bin:/usr/local/go/bin"
ENV PARALLEL_JOBS=9000
ENV J=9000

# Create kali user and set up directories
RUN useradd -m -s /bin/bash kali && \
    echo 'kali:kali' | chpasswd && \
    mkdir -p /home/kali/go/{bin,src,pkg} && \
    mkdir -p /home/kali/results && \
    mkdir -p /home/kali/wordlists

# Update system and install essential packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
        curl wget git build-essential \
        python3 python3-pip python3-dev \
        golang-go nodejs npm \
        parallel jq \
        nmap masscan \
        dnsutils net-tools \
        vim nano htop \
        ca-certificates \
        unzip zip \
        libssl-dev libffi-dev \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Go security tools in parallel for faster builds
RUN su - kali -c "export GOPATH=/home/kali/go && export PATH=\$PATH:/home/kali/go/bin:/usr/local/go/bin && \
    echo 'Installing Go security tools...' && \
    parallel -j8 'go install {}@latest' ::: \
        'github.com/projectdiscovery/nuclei/v3/cmd/nuclei' \
        'github.com/projectdiscovery/subfinder/v2/cmd/subfinder' \
        'github.com/projectdiscovery/httpx/cmd/httpx' \
        'github.com/projectdiscovery/dnsx/cmd/dnsx' \
        'github.com/projectdiscovery/naabu/v2/cmd/naabu' \
        'github.com/projectdiscovery/katana/cmd/katana' \
        'github.com/ffuf/ffuf/v2' \
        'github.com/tomnomnom/waybackurls' \
        'github.com/tomnomnom/assetfinder' \
        'github.com/tomnomnom/qsreplace' \
        'github.com/tomnomnom/unfurl' \
        'github.com/lc/gau/v2/cmd/gau' \
        'github.com/hahwul/dalfox/v2'"

# Install Python security tools
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    pip3 install --no-cache-dir \
        sqlmap dirsearch paramspider arjun \
        xsstrike gitdorker cloudhunter \
        wafw00f whatwaf && \
    rm /tmp/requirements.txt

# Set up file descriptor limits for high-performance scanning
RUN echo "* soft nofile 65536" >> /etc/security/limits.conf && \
    echo "* hard nofile 65536" >> /etc/security/limits.conf && \
    echo "fs.file-max = 1000000" >> /etc/sysctl.conf

# Copy framework files
COPY . /home/kali/dotfiles/
RUN chown -R kali:kali /home/kali/

# Set up user environment
USER kali
WORKDIR /home/kali

# Set up security aliases and functions
RUN echo 'source /home/kali/dotfiles/.security_aliases' >> ~/.bashrc && \
    echo 'export GOPATH=/home/kali/go' >> ~/.bashrc && \
    echo 'export PATH="$PATH:/home/kali/go/bin"' >> ~/.bashrc && \
    echo 'export J=9000' >> ~/.bashrc

# Update Nuclei templates
RUN /home/kali/go/bin/nuclei -update-templates || true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nuclei -version && subfinder -version && httpx -version || exit 1

# Set entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
USER root
RUN chmod +x /entrypoint.sh
USER kali

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]