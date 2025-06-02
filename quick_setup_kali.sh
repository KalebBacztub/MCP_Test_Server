#!/bin/bash

# Quick setup script for Kali Linux MCP Security Testing Server
# Usage: ./quick_setup_kali.sh <TARGET_IP> <TARGET_PORT> <OPENROUTER_API_KEY>

set -e

echo "🔥 MCP Security Testing Server - Kali Linux Setup 🔥"
echo "=================================================="

# Check if parameters provided
if [ $# -ne 3 ]; then
    echo "Usage: $0 <TARGET_IP> <TARGET_PORT> <OPENROUTER_API_KEY>"
    echo "Example: $0 192.168.1.100 8080 sk-or-v1-your-key-here"
    exit 1
fi

TARGET_IP=$1
TARGET_PORT=$2
OPENROUTER_API_KEY=$3
TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}"

echo "Target: $TARGET_URL"
echo "Setting up MCP Security Testing environment..."

# Create project directory
PROJECT_DIR="$HOME/mcp-security-testing"
echo "📁 Creating project directory: $PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

# Test connectivity first
echo "🔗 Testing connectivity to target..."
if ping -c 1 "$TARGET_IP" &> /dev/null; then
    echo "✅ Target IP is reachable"
else
    echo "❌ Target IP is not reachable. Check network connectivity."
    exit 1
fi

if nc -z "$TARGET_IP" "$TARGET_PORT" 2>/dev/null; then
    echo "✅ Target port $TARGET_PORT is open"
else
    echo "⚠️  Target port $TARGET_PORT appears closed or filtered"
    echo "   Continuing anyway - it might be filtered but still accessible via HTTP"
fi

# Test HTTP connectivity
echo "🌐 Testing HTTP connectivity..."
if curl -s --connect-timeout 5 "$TARGET_URL" &> /dev/null; then
    echo "✅ HTTP connection successful"
else
    echo "⚠️  HTTP connection failed, but continuing setup"
fi

# Update system packages
echo "📦 Updating system packages..."
sudo apt update

# Install required packages
echo "🔧 Installing required packages..."
sudo apt install -y python3 python3-pip python3-venv git curl netcat-traditional

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Create requirements.txt
echo "📋 Creating requirements.txt..."
cat > requirements.txt << 'EOF'
mcp>=1.0.0
aiohttp>=3.8.0
requests>=2.31.0
python-dotenv>=1.0.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
urllib3>=1.26.0
EOF

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create environment file
echo "⚙️  Creating environment configuration..."
cat > .env << EOF
OPENROUTER_API_KEY=$OPENROUTER_API_KEY
TARGET_URL=$TARGET_URL
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
LOG_LEVEL=INFO
EOF

# Create the MCP server file (placeholder - user needs to copy the actual content)
echo "📝 Creating MCP server file placeholder..."
cat > mcp_security_server.py << 'EOF'
#!/usr/bin/env python3
"""
MCP Server for AI-powered web security testing using OpenRouter
Copy the actual server code from the provided artifact into this file.
"""

print("Please copy the MCP server code from the artifact into this file.")
print("The server code is provided in the 'mcp_security_server.py' artifact.")
EOF

# Create logs directory
mkdir -p logs

# Create helper scripts
echo "🛠️  Creating helper scripts..."

# Connectivity test script
cat > test_connectivity.sh << EOF
#!/bin/bash
echo "Testing connectivity to $TARGET_URL"
echo "=================================="
echo "1. Ping test:"
ping -c 3 $TARGET_IP

echo -e "\n2. Port test:"
nc -zv $TARGET_IP $TARGET_PORT

echo -e "\n3. HTTP test:"
curl -I --connect-timeout 10 $TARGET_URL

echo -e "\n4. OpenRouter API test:"
curl -H "Authorization: Bearer $OPENROUTER_API_KEY" \
     -H "Content-Type: application/json" \
     https://openrouter.ai/api/v1/models | head -20
EOF

chmod +x test_connectivity.sh

# Quick test script
cat > quick_test.py << 'EOF'
#!/usr/bin/env python3
"""
Quick test script to verify MCP server functionality
"""
import asyncio
import aiohttp
import os
from dotenv import load_dotenv

load_dotenv()

async def test_target():
    target_url = os.getenv('TARGET_URL')
    print(f"Testing connection to: {target_url}")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=10) as response:
                print(f"Status: {response.status}")
                print(f"Headers: {dict(response.headers)}")
                content = await response.text()
                print(f"Content length: {len(content)} bytes")
                return True
    except Exception as e:
        print(f"Connection failed: {str(e)}")
        return False

async def test_openrouter():
    api_key = os.getenv('OPENROUTER_API_KEY')
    print("Testing OpenRouter API connection...")
    
    try:
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get('https://openrouter.ai/api/v1/models', headers=headers) as response:
                if response.status == 200:
                    print("✅ OpenRouter API connection successful")
                    return True
                else:
                    print(f"❌ OpenRouter API error: {response.status}")
                    return False
    except Exception as e:
        print(f"❌ OpenRouter API failed: {str(e)}")
        return False

async def main():
    print("🧪 Running connectivity tests...")
    print("=" * 40)
    
    target_ok = await test_target()
    api_ok = await test_openrouter()
    
    print("\n" + "=" * 40)
    if target_ok and api_ok:
        print("✅ All tests passed! Ready to run MCP server.")
    else:
        print("❌ Some tests failed. Check configuration.")

if __name__ == "__main__":
    asyncio.run(main())
EOF

chmod +x quick_test.py

# Create run script
cat > run_server.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python mcp_security_server.py
EOF

chmod +x run_server.sh

echo ""
echo "🎉 Setup completed successfully!"
echo "================================"
echo ""
echo "📁 Project location: $PROJECT_DIR"
echo "🎯 Target: $TARGET_URL"
echo "🔑 API Key: ${OPENROUTER_API_KEY:0:20}..."
echo ""
echo "Next steps:"
echo "1. Copy the MCP server code into mcp_security_server.py"
echo "2. Test connectivity: ./test_connectivity.sh"
echo "3. Run quick test: python quick_test.py"
echo "4. Start the server: ./run_server.sh"
echo ""
echo "🚨 IMPORTANT: Copy the actual MCP server code from the artifact!"
echo "   The current mcp_security_server.py file is just a placeholder."

# Run connectivity test
echo ""
echo "Running initial connectivity test..."
./test_connectivity.sh