#!/usr/bin/env python3
"""
Conceptual MCP Client to interact with the stdio-based mcp_security_server.py
"""
import json
import subprocess
import threading
import queue
import time
import os

# --- Configuration ---
# Path to the directory containing run_server.sh and mcp_security_server.py
MCP_SERVER_DIR = os.path.expanduser("~/MCP_Test_Server/MCP Test") # Adjust if necessary
RUN_SERVER_SCRIPT = "./run_server.sh"

# --- Helper Functions ---
def read_output(pipe, q, stream_name):
    """Reads lines from a pipe and puts them into a queue."""
    try:
        for line in iter(pipe.readline, b''):
            if not line: # Handle EOF
                break
            decoded_line = line.decode('utf-8').strip()
            q.put((stream_name, decoded_line))
            # print(f"DEBUG Raw {stream_name}: {decoded_line}", flush=True) # Optional: for debugging client's raw reads
    except Exception as e:
        q.put((stream_name, f"Error reading {stream_name}: {e}"))
    finally:
        pipe.close()
        q.put((stream_name, None)) # Signal EOF for this stream

class MCPStdioClient:
    def __init__(self, server_dir, run_script):
        self.server_dir = server_dir
        self.run_script = run_script
        self.process = None
        self.output_queue = queue.Queue()
        self.stdout_thread = None
        self.stderr_thread = None
        self.request_id_counter = 1

    def start_server(self):
        """Starts the MCP server as a subprocess."""
        try:
            print(f"Starting MCP server using '{self.run_script}' in '{self.server_dir}'...")
            # We expect run_server.sh to handle its own virtualenv activation
            self.process = subprocess.Popen(
                [self.run_script],
                cwd=self.server_dir,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,  # Line buffered
                # shell=True # If run_server.sh needs shell features, but generally safer to avoid
            )
            print(f"MCP server process started (PID: {self.process.pid}).")

            # Start threads to read stdout and stderr
            self.stdout_thread = threading.Thread(
                target=read_output,
                args=(self.process.stdout, self.output_queue, "stdout"),
                daemon=True
            )
            self.stderr_thread = threading.Thread(
                target=read_output,
                args=(self.process.stderr, self.output_queue, "stderr"),
                daemon=True
            )
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Give the server a moment to initialize
            time.sleep(5) # Adjust as needed, run_server.sh has its own sleep
            print("Client is ready to send commands.")
            return True
        except Exception as e:
            print(f"Error starting MCP server: {e}")
            return False

    def stop_server(self):
        """Stops the MCP server."""
        if self.process:
            print("Stopping MCP server...")
            if self.process.stdin:
                try:
                    self.process.stdin.close() # Signal EOF to server's stdin
                except Exception:
                    pass # Ignore errors if already closed
            
            # Give server a chance to shut down from stdin close
            try:
                self.process.wait(timeout=5) # Wait for graceful shutdown
            except subprocess.TimeoutExpired:
                print("Server did not shut down gracefully, terminating...")
                self.process.terminate() # Try to terminate
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    print("Server did not terminate, killing...")
                    self.process.kill() # Force kill

            if self.stdout_thread and self.stdout_thread.is_alive():
                self.stdout_thread.join(timeout=1)
            if self.stderr_thread and self.stderr_thread.is_alive():
                self.stderr_thread.join(timeout=1)
            
            self.process = None
            print("MCP server stopped.")

    def send_command(self, tool_name, arguments):
        """Sends a command to the MCP server and waits for a response."""
        if not self.process or not self.process.stdin:
            print("Server not running or stdin not available.")
            return None

        request_id = self.request_id_counter
        self.request_id_counter += 1

        # Construct the JSON-RPC message
        # Based on typical MCP, a tool call might look like this.
        # Your server might expect a simpler format if mcp-python's stdio_server handles wrapping.
        # The examples in SetupGuide.md are simpler. Let's try simpler first, then JSON-RPC if needed.
        # command_obj = {
        #     "tool": tool_name,
        #     "arguments": arguments
        # }
        command_obj = {
            "jsonrpc": "2.0",
            "method": "tools/call", # Common MCP method for tool calls
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": request_id
        }
        
        command_str = json.dumps(command_obj) + "\n" # Ensure newline for line-based reading

        try:
            print(f"Sending command (ID {request_id}): {command_obj}")
            self.process.stdin.write(command_str.encode('utf-8'))
            self.process.stdin.flush()
        except Exception as e:
            print(f"Error sending command: {e}")
            return None

        # Wait for and process responses
        # This is a simplified response handling. Real MCP clients have more robust
        # handling for matching response IDs, notifications, etc.
        print(f"Waiting for response to ID {request_id} (and other server output)...")
        response_data = []
        stdout_eof = False
        stderr_eof = False
        
        # Simple timeout mechanism for response gathering
        timeout_at = time.time() + 20 # Wait up to 20 seconds for a response bundle
        
        while time.time() < timeout_at:
            try:
                stream, line = self.output_queue.get(timeout=1)
                if line is None: # EOF for that stream
                    if stream == "stdout": stdout_eof = True
                    if stream == "stderr": stderr_eof = True
                    if stdout_eof and stderr_eof: # Both streams closed by server
                        break
                    continue

                print(f"Server ({stream}): {line}")
                if stream == "stdout":
                    try:
                        # Attempt to parse as JSON if it's from stdout
                        json_response = json.loads(line)
                        # Basic check if this might be the response we're looking for
                        if isinstance(json_response, dict) and json_response.get("id") == request_id:
                            print(f"Received targeted response for ID {request_id}: {json_response}")
                            response_data.append(json_response) # Could be multiple parts for one response
                            # For simplicity, we'll break after the first matching ID response.
                            # A real client would handle streaming responses or multiple messages.
                            return json_response # Return the primary response
                        elif isinstance(json_response, dict) and "result" in json_response or "error" in json_response:
                            # Generic response or notification
                            response_data.append(json_response)
                    except json.JSONDecodeError:
                        # Not a JSON line, just server stdout logging
                        pass # Already printed
            except queue.Empty:
                # Queue is empty, check if server might still be processing or if we should break
                if self.process.poll() is not None: # Server process has terminated
                    print("Server process terminated while waiting for response.")
                    break
                # Continue waiting if timeout not reached
                pass
            except Exception as e:
                print(f"Error processing server output: {e}")
                break
        
        if not response_data:
            print(f"No specific JSON-RPC response received for ID {request_id} within timeout.")
        # Return all collected JSON responses if no specific one was targeted, or the last one.
        return response_data if response_data else "Timeout or no specific JSON-RPC response."


# --- Main ---
if __name__ == "__main__":
    client = MCPStdioClient(server_dir=MCP_SERVER_DIR, run_script=RUN_SERVER_SCRIPT)
    
    if not client.start_server():
        print("Exiting due to server start failure.")
        exit(1)

    print("\nMCP Client Interactive Mode")
    print("Type 'quit' or 'exit' to stop.")
    print("Enter tool name (e.g., web_request, spider_application, analyze_with_ai, security_scan)")
    print("You will be prompted for arguments as a JSON string.")
    print("Example tool: web_request")
    print("Example arguments JSON: {\"method\": \"GET\", \"path\": \"/\"}")

    try:
        while True:
            print("-" * 30)
            tool_name = input("Enter tool name (or 'quit'): ").strip()
            if tool_name.lower() in ['quit', 'exit']:
                break
            if not tool_name:
                continue

            arguments_json_str = input(f"Enter arguments for '{tool_name}' (as JSON string): ").strip()
            try:
                arguments = json.loads(arguments_json_str)
            except json.JSONDecodeError as e:
                print(f"Invalid JSON for arguments: {e}")
                continue
            
            print("\nSending command...")
            response = client.send_command(tool_name, arguments)
            
            print("\n--- Response from Server ---")
            if response:
                print(json.dumps(response, indent=2))
            else:
                print("No structured response received or error occurred.")
            print("--- End of Response ---")

    except KeyboardInterrupt:
        print("\nClient interrupted.")
    finally:
        client.stop_server()
    print("Client finished.")
