#!/bin/bash

# Fix environment issues script
echo "🔧 MCP Environment Fix Script"
echo "============================="

# Check current directory
echo "📁 Current directory: $(pwd)"

# Check if we're in the right directory
if [ ! -f "requirements.txt" ] && [ ! -f "mcp_security_server.py" ]; then
    echo "❌ Not in MCP project directory!"
    echo "   Please cd to your MCP project directory first"
    echo "   Usually: cd ~/mcp-security-testing"
    exit 1
fi

# Check .env file
if [ ! -f ".env" ]; then
    echo "❌ .env file missing! Creating template..."
    cat > .env << 'EOF'
OPENROUTER_API_KEY=your_openrouter_api_key_here
TARGET_URL=http://192.168.1.100:8080
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
LOG_LEVEL=INFO
EOF
    echo "✅ Created .env template"
    echo "   Please edit .env and add your actual OpenRouter API key!"
    echo "   nano .env"
else
    echo "✅ .env file exists"
fi

# Show current .env contents (masked)
echo ""
echo "📋 Current .env contents:"
while IFS= read -r line; do
    if [[ $line == *"OPENROUTER_API_KEY"* ]]; then
        if [[ $line == *"your_openrouter_api_key_here"* ]]; then
            echo "   ❌ $line (NEEDS TO BE UPDATED!)"
        else
            # Mask the API key
            key=$(echo "$line" | cut -d'=' -f1)
            echo "   ✅ ${key}=sk-or-v1-*****(masked)"
        fi
    else
        echo "   $line"
    fi
done < .env

# Check if API key needs updating
grep -q "your_openrouter_api_key_here" .env
if [ $? -eq 0 ]; then
    echo ""
    echo "🚨 IMPORTANT: You need to update your API key in .env!"
    echo "   1. Get API key from: https://openrouter.ai/"
    echo "   2. Edit .env file: nano .env"
    echo "   3. Replace 'your_openrouter_api_key_here' with your actual key"
    echo ""
    read -p "Do you want to edit .env now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        nano .env
    fi
fi

# Test environment loading
echo ""
echo "🧪 Testing environment loading..."
if [ -f "debug_env.py" ]; then
    python debug_env.py
else
    echo "   debug_env.py not found, creating it..."
    # Create debug_env.py if it doesn't exist
    cat > debug_env.py << 'EOF'
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv('OPENROUTER_API_KEY')
target_url = os.getenv('TARGET_URL')

print(f"API Key loaded: {'Yes' if api_key else 'No'}")
print(f"Target URL: {target_url}")

if api_key and not api_key.startswith('your_'):
    print("✅ Environment looks good!")
else:
    print("❌ Please update your .env file with real values")
EOF
    python debug_env.py
fi

echo ""
echo "🎯 Next steps:"
echo "   1. Make sure .env has your real OpenRouter API key"
echo "   2. Update TARGET_URL with your Proxmox VM IP"
echo "   3. Run: ./run_server.sh"