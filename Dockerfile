FROM kalilinux/kali-rolling
WORKDIR /app

RUN apt-get update -q && apt-get install -y -q \
    python3 python3-pip golang-go ruby git curl wget \
    nmap nikto gobuster ffuf masscan dnsrecon whois \
    enum4linux smbmap wafw00f theharvester whatweb \
    dnsutils ldap-utils samba-common-bin rpcclient \
    exploitdb metasploit-framework && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH=$PATH:/root/go/bin
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true

COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

RUN curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null || true

COPY . .
RUN nuclei -update-templates -silent 2>/dev/null || true

EXPOSE 5000
CMD ["python3", "app.py"]
