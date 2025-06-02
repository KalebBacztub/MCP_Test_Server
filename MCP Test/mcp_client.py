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
MCP_SERVER_DIR = os.path.expanduser("~/MCP_Test_Server/MCP Test") # Adjust if necessary
RUN_SERVER_SCRIPT = "./run_server.sh"

# --- Helper Functions ---
def read_output(pipe, q, stream_name):
    try:
        for line in iter(pipe.readline, b''):
            if not line: break
            decoded_line = line.decode('utf-8').strip()
            q.put((stream_name, decoded_line))
    except Exception as e:
        q.put((stream_name, f"Error reading {stream_name}: {e}"))
    finally:
        pipe.close()
        q.put((stream_name, None))

class MCPStdioClient:
    def __init__(self, server_dir, run_script):
        self.server_dir = server_dir
        self.run_script = run_script
        self.process = None
        self.output_queue = queue.Queue()
        self.stdout_thread = None
        self.stderr_thread = None
        self.request_id_counter = 0 # Start at 0 for initialize, then increment

    def start_server(self):
        try:
            print(f"Starting MCP server using '{self.run_script}' in '{self.server_dir}'...")
            self.process = subprocess.Popen(
                [self.run_script],
                cwd=self.server_dir,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
            )
            print(f"MCP server process started (PID: {self.process.pid}).")

            self.stdout_thread = threading.Thread(target=read_output, args=(self.process.stdout, self.output_queue, "stdout"), daemon=True)
            self.stderr_thread = threading.Thread(target=read_output, args=(self.process.stderr, self.output_queue, "stderr"), daemon=True)
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            time.sleep(3) # Reduced sleep, initialize will confirm readiness
            return True
        except Exception as e:
            print(f"Error starting MCP server: {e}")
            return False

    def _send_json_rpc_request(self, method, params, request_id=None):
        if not self.process or not self.process.stdin:
            print("Server not running or stdin not available.")
            return None
        
        if request_id is None:
            self.request_id_counter +=1
            request_id = self.request_id_counter

        command_obj = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }
        command_str = json.dumps(command_obj) + "\n"

        try:
            print(f"Sending request (ID {request_id}): {json.dumps(command_obj, indent=2)}")
            self.process.stdin.write(command_str.encode('utf-8'))
            self.process.stdin.flush()
            return request_id
        except Exception as e:
            print(f"Error sending request: {e}")
            return None

    def _wait_for_response(self, request_id, timeout=20):
        print(f"Waiting for response to ID {request_id} (and other server output)...")
        response_data_for_id = None
        # Drain queue for a bit, printing all messages and looking for the one with our ID
        timeout_at = time.time() + timeout
        
        while time.time() < timeout_at:
            try:
                stream, line = self.output_queue.get(timeout=1)
                if line is None: # EOF signal from read_output
                    # Check if it's for stdout or stderr and if both are done
                    # For simplicity, we assume if one stream ends, things might be shutting down.
                    print(f"EOF received on {stream} while waiting for ID {request_id}.")
                    break 

                print(f"Server ({stream}): {line}")
                if stream == "stdout":
                    try:
                        json_response = json.loads(line)
                        if isinstance(json_response, dict) and json_response.get("id") == request_id:
                            print(f"Received targeted response for ID {request_id}: {json.dumps(json_response, indent=2)}")
                            response_data_for_id = json_response
                            break # Found our response
                    except json.JSONDecodeError:
                        pass # Not a JSON line, just server stdout logging
            except queue.Empty:
                if self.process.poll() is not None: # Server process has terminated
                    print("Server process terminated while waiting for response.")
                    break
            except Exception as e:
                print(f"Error processing server output: {e}")
                break
        
        if not response_data_for_id:
             print(f"No specific JSON-RPC response for ID {request_id} found within timeout or server output ended.")
        return response_data_for_id

    def send_initialize_request(self):
        """Sends the initialize request to the server."""
        print("\nSending InitializeRequest...")
        init_params = {
            "protocolVersion": "1.0", # Or "2.0", check MCP spec if available
            "clientInfo": {
                "name": "MyConceptualMCPClient",
                "version": "0.1.1"
            },
            "capabilities": {} # Client capabilities, empty for now
            # "processId": os.getpid() # Optional: some clients send their PID
        }
        request_id = self._send_json_rpc_request(method="initialize", params=init_params, request_id=0) # ID 0 is common for init
        if request_id is not None:
            response = self._wait_for_response(request_id)
            if response and "result" in response:
                print("Initialization successful. Server capabilities:")
                print(json.dumps(response["result"], indent=2))
                return True
            elif response and "error" in response:
                print("Initialization failed:")
                print(json.dumps(response["error"], indent=2))
                return False
            else:
                print("No definitive success/failure response for initialize.")
                return False
        return False

    def send_tool_call(self, tool_name, arguments):
        """Sends a tools/call request to the MCP server."""
        params = {
            "name": tool_name,
            "arguments": arguments
        }
        request_id = self._send_json_rpc_request(method="tools/call", params=params)
        if request_id is not None:
            return self._wait_for_response(request_id)
        return None

    def stop_server(self):
        if self.process:
            print("Stopping MCP server...")
            if self.process.stdin and not self.process.stdin.closed:
                try: self.process.stdin.close()
                except Exception: pass
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Server did not shut down gracefully, terminating...")
                self.process.terminate()
                try: self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    print("Server did not terminate, killing...")
                    self.process.kill()
            if self.stdout_thread and self.stdout_thread.is_alive(): self.stdout_thread.join(timeout=1)
            if self.stderr_thread and self.stderr_thread.is_alive(): self.stderr_thread.join(timeout=1)
            self.process = None
            print("MCP server stopped.")

# --- Main ---
if __name__ == "__main__":
    client = MCPStdioClient(server_dir=MCP_SERVER_DIR, run_script=RUN_SERVER_SCRIPT)
    
    if not client.start_server():
        print("Exiting due to server start failure.")
        exit(1)

    # Attempt to initialize the server
    if not client.send_initialize_request():
        print("Server initialization failed. Exiting client.")
        client.stop_server()
        exit(1)
    
    print("\nMCP Client Interactive Mode (Server Initialized)")
    print("Type 'quit' or 'exit' to stop.")
    # ... (rest of the interactive loop from previous client script) ...
    try:
        while True:
            print("-" * 30)
            tool_name = input("Enter tool name (or 'quit'): ").strip()
            if tool_name.lower() in ['quit', 'exit']:
                break
            if not tool_name:
                continue

            arguments_json_str = input(f"Enter arguments for '{tool_name}' (as JSON string, e.g., {{\}} or {{\"key\": \"value\"}}): ").strip()
            try:
                arguments = json.loads(arguments_json_str)
            except json.JSONDecodeError as e:
                print(f"Invalid JSON for arguments: {e}")
                continue
            
            print("\nSending tool call...")
            response = client.send_tool_call(tool_name, arguments) # Changed to send_tool_call
            
            print("\n--- Response from Server ---")
            if response:
                print(json.dumps(response, indent=2))
            else:
                print("No structured response received or error occurred for tool call.")
            print("--- End of Response ---")

    except KeyboardInterrupt:
        print("\nClient interrupted.")
    finally:
        client.stop_server()
    print("Client finished.")
