# VulnX all-in-one image: the web app plus the scanning stack
# (nmap, Metasploit, curl, openssl) in a single container. VulnX
# connects to the scanner over the container's own localhost SSH, so
# no separate Kali VM is needed. Runs on Windows, macOS, or Linux
# through Docker.

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Scanning + runtime dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        metasploit-framework \
        openssh-server \
        curl \
        openssl \
        postgresql \
        python3 \
        python3-pip \
        sudo \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Local scanner user that VulnX logs into over 127.0.0.1 SSH.
# Password is "kali" (type it in the scan form's Kali SSH Password field).
RUN useradd -m -s /bin/bash kali \
    && echo 'kali:kali' | chpasswd \
    && adduser kali sudo \
    && mkdir -p /var/run/sshd

WORKDIR /app

# Install Python dependencies first, in their own layer. This is cached
# on requirements.txt, so editing the app code later does NOT re-run pip.
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Then copy the application code.
COPY . /app
RUN chmod +x /app/docker/entrypoint.sh

# Run fully self-contained: scan via localhost, bind to all interfaces
# so the host can reach the web UI, debug off.
ENV VULNX_SCANNER_HOST=127.0.0.1 \
    VULNX_SCANNER_USER=kali \
    VULNX_BIND=0.0.0.0 \
    VULNX_PORT=5000 \
    VULNX_DEBUG=0

EXPOSE 5000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
