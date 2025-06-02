#!/bin/bash

# Enhanced run script with debugging
echo "🚀 Starting MCP Security Testing Server"
echo "======================================"

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "📁 Script directory: $SCRIPT_DIR"

# Change to script directory
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "   Please run the setup script first or create venv manually:"
    echo "   python3 -m venv venv"
    exit 1
fi

# Activate virtual environment
echo "🐍 Activating virtual environment..."
source venv/bin/activate

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found!"
    echo "   Please create .env file with:"
    echo "   OPENROUTER_API_KEY=your_api_key_here"
    echo "   TARGET_URL=http://your_target_ip:port"
    exit 1
fi

# Check if MCP server file exists
if [ ! -f "mcp_security_server.py" ]; then
    echo "❌ mcp_security_server.py not found!"
    echo "   Please copy the MCP server code from the artifact."
    exit 1
fi

# Show environment info
echo "🔍 Environment check:"
echo "   .env file: ✅"
echo "   MCP server: ✅"
echo "   Virtual env: ✅"

# Debug environment variables
echo ""
echo "🧪 Running environment debug..."
python debug_env.py

echo ""
echo "🎯 Starting MCP Security Server..."
echo "   Press Ctrl+C to stop"
echo ""

# Run the server
python mcp_security_server.py