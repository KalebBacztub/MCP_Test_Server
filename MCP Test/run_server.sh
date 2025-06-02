#!/bin/bash

# Enhanced MCP Security Testing Server Runner for Kali Linux
# Includes comprehensive error checking and debugging

set -e  # Exit on any error

echo "🔥 MCP Security Testing Server - Kali Linux 🔥"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
print_info "Script directory: $SCRIPT_DIR"

# Change to script directory
cd "$SCRIPT_DIR"

echo ""
echo "🔍 System Check"
echo "==============="

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_success "Python available: $PYTHON_VERSION"
else
    print_error "Python3 not found! Install with: sudo apt install python3"
    exit 1
fi

# Check pip
if command -v pip3 &> /dev/null || python3 -m pip --version &> /dev/null; then
    print_success "pip3 available"
else
    print_error "pip3 not found! Install with: sudo apt install python3-pip"
    exit 1
fi

# Check if virtual environment exists
echo ""
echo "🐍 Virtual Environment Check"
echo "============================"

if [ ! -d "venv" ]; then
    print_warning "Virtual environment not found! Creating one..."
    python3 -m venv venv
    if [ $? -eq 0 ]; then
        print_success "Virtual environment created"
    else
        print_error "Failed to create virtual environment"
        exit 1
    fi
else
    print_success "Virtual environment exists"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

if [ $? -eq 0 ]; then
    print_success "Virtual environment activated"
    print_info "Python path: $(which python)"
else
    print_error "Failed to activate virtual environment"
    exit 1
fi

# Check and install requirements
echo ""
echo "📚 Dependencies Check"
echo "===================="

if [ ! -f "requirements.txt" ]; then
    print_warning "requirements.txt not found! Creating it..."
    cat > requirements.txt << 'EOF'
mcp>=1.0.0
aiohttp>=3.8.0
requests>=2.31.0
python-dotenv>=1.0.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
urllib3>=1.26.0
EOF
    print_success "Created requirements.txt"
fi

# Check if packages are installed
print_info "Checking Python packages..."
if ! python -c "import mcp, aiohttp, requests, dotenv" &> /dev/null; then
    print_warning "Some packages missing. Installing requirements..."
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        print_success "Dependencies installed"
    else
        print_error "Failed to install dependencies"
        exit 1
    fi
else
    print_success "All required packages available"
fi

# Check environment file
echo ""
echo "⚙️  Environment Configuration"
echo "============================"

if [ ! -f ".env" ]; then
    print_error ".env file not found!"
    print_info "Creating template .env file..."
    cat > .env << 'EOF'
# MCP Security Server Environment Configuration
OPENROUTER_API_KEY=your_openrouter_api_key_here
TARGET_URL=http://192.168.1.100:8080
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
LOG_LEVEL=INFO
EOF
    print_warning "Please edit .env file with your actual configuration:"
    print_info "nano .env"
    exit 1
else
    print_success ".env file exists"
fi

# Check if .env has been configured
if grep -q "your_openrouter_api_key_here" .env; then
    print_error ".env file contains placeholder values!"
    print_info "Please update .env with your actual OpenRouter API key"
    print_info "Edit with: nano .env"
    exit 1
fi

# Check MCP server file
echo ""
echo "📝 MCP Server File Check"
echo "======================="

if [ ! -f "mcp_security_server.py" ]; then
    print_error "mcp_security_server.py not found!"
    print_info "Please copy the MCP server code from the artifact."
    exit 1
else
    print_success "MCP server file exists"
fi

# Make sure it's executable
chmod +x mcp_security_server.py

# Create logs directory if it doesn't exist
if [ ! -d "logs" ]; then
    mkdir -p logs
    print_success "Created logs directory"
fi

# Run environment debug if available
echo ""
echo "🧪 Environment Diagnostics"
echo "========================="

if [ -f "debug_env.py" ]; then
    print_info "Running environment diagnostics..."
    python debug_env.py
    
    # MODIFICATION START: Comment out or remove the interactive prompt block
    # echo ""
    # read -p "Do you want to continue starting the server? (y/n): " -n 1 -r
    # echo
    # if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    #     print_info "Exiting. Fix any issues and run again."
    #     exit 0
    # fi
    print_info "Proceeding to start server after diagnostics..." # Add a message
    # MODIFICATION END
else
    print_warning "debug_env.py not found - skipping diagnostics"
fi

# Network connectivity check
echo ""
echo "🌐 Network Connectivity Check"
echo "============================"

# Extract target URL from .env
TARGET_URL=$(grep "^TARGET_URL=" .env | cut -d'=' -f2)
if [ ! -z "$TARGET_URL" ]; then
    print_info "Testing connectivity to: $TARGET_URL"
    
    # Extract IP and port
    TARGET_HOST=$(echo $TARGET_URL | sed 's|http[s]*://||' | cut -d':' -f1)
    TARGET_PORT=$(echo $TARGET_URL | sed 's|http[s]*://||' | cut -d':' -f2 | cut -d'/' -f1)
    
    # Ping test
    if ping -c 1 -W 3 $TARGET_HOST &> /dev/null; then
        print_success "Target host is reachable"
    else
        print_warning "Target host ping failed (might be filtered)"
    fi
    
    # Port test (if netcat is available)
    if command -v nc &> /dev/null; then
        if nc -z -w3 $TARGET_HOST $TARGET_PORT 2>/dev/null; then
            print_success "Target port $TARGET_PORT is open"
        else
            print_warning "Target port $TARGET_PORT appears closed or filtered"
        fi
    fi
    
    # HTTP test
    if command -v curl &> /dev/null; then
        if curl -s --connect-timeout 5 --max-time 10 $TARGET_URL > /dev/null 2>&1; then
            print_success "HTTP connection successful"
        else
            print_warning "HTTP connection failed"
        fi
    fi
fi

# Final checks and startup
echo ""
echo "🚀 Starting MCP Security Server"
echo "=============================="

print_success "All checks passed!"
print_info "Server will start in 3 seconds..."
print_info "Press Ctrl+C to stop the server"
print_info "Logs will be saved to the logs/ directory"

sleep 3

# Set up signal handling for graceful shutdown
trap 'echo -e "\n🛑 Shutting down MCP server..."; exit 0' INT TERM

# Start the server with error handling
echo ""
print_info "Starting MCP Security Testing Server..."
echo "----------------------------------------"

# Run with timeout and error recovery
timeout 300 python mcp_security_server.py 2>&1 | tee logs/server_$(date +%Y%m%d_%H%M%S).log

EXIT_CODE=$?

if [ $EXIT_CODE -eq 124 ]; then
    print_warning "Server stopped due to timeout (5 minutes)"
elif [ $EXIT_CODE -ne 0 ]; then
    print_error "Server exited with error code: $EXIT_CODE"
    print_info "Check the logs in logs/ directory for more details"
else
    print_success "Server shutdown normally"
fi

print_info "Session ended at $(date)"
