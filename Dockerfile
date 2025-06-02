FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the MCP server code
COPY mcp_security_server.py .

# Create logs directory
RUN mkdir -p logs

# Make the script executable
RUN chmod +x mcp_security_server.py

# Run the MCP server
CMD ["python", "mcp_security_server.py"]