#!/usr/bin/env python3
"""
MCP Server for AI-powered web security testing using OpenRouter
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
import aiohttp
# import requests # Not actively used, can be removed if not needed elsewhere
from mcp.server import Server, NotificationOptions # MODIFIED: Added NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    # ImageContent, # Not used in current tool definitions
    # EmbeddedResource, # Not used in current tool definitions
)
import os
from urllib.parse import urljoin # urlparse not used
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s' # Added a basic format
)
logger = logging.getLogger(__name__) # Ensures logger is defined for the module

class SecurityTestingMCPServer:
    def __init__(self):
        self.server = Server("security-testing-mcp")
        
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        self.target_url = os.getenv("TARGET_URL", "http://192.168.1.100:8080")
        self.session = None # aiohttp session, initialized on first use
        
        # Debug: Print environment info - this will go to stderr via print
        # and might be captured differently by `run_server.sh`'s tee than logger.info
        print(f"🔍 MCP_SERVER_INIT: Debug Info:")
        print(f"   Current working directory: {os.getcwd()}")
        print(f"   .env file exists: {os.path.exists('.env')}")
        print(f"   TARGET_URL: {self.target_url}")
        print(f"   API Key present: {'Yes' if self.openrouter_api_key else 'No'}")
        
        if not self.openrouter_api_key:
            print("❌ MCP_SERVER_INIT: OPENROUTER_API_KEY not found!")
            print("   Please check your .env file contains:")
            print("   OPENROUTER_API_KEY=your_actual_api_key_here")
            # Raising an error here will stop the server from starting if key is missing
            raise ValueError("OPENROUTER_API_KEY environment variable is required")
        
        print(f"✅ MCP_SERVER_INIT: Environment loaded successfully")
        self.setup_handlers()
    
    def setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            logger.info("@@@ MCP_SERVER: handle_list_resources called")
            return [
                Resource(
                    uri="security://target-info",
                    name="Target Application Info",
                    description="Information about the target web application",
                    mimeType="application/json",
                ),
                Resource(
                    uri="security://test-results",
                    name="Security Test Results",
                    description="Results from security tests performed",
                    mimeType="application/json",
                ),
            ]
        
        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            logger.info(f"@@@ MCP_SERVER: handle_read_resource called for URI: {uri}")
            if uri == "security://target-info":
                return json.dumps({
                    "target_url": self.target_url,
                    "status": "active",
                    "last_checked": time.time()
                })
            elif uri == "security://test-results":
                return json.dumps({
                    "tests_performed": [],
                    "vulnerabilities_found": [],
                    "last_scan": None
                })
            else:
                logger.warning(f"@@@ MCP_SERVER: Unknown resource requested: {uri}")
                raise ValueError(f"Unknown resource: {uri}")
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            logger.info("@@@ MCP_SERVER: handle_list_tools called")
            return [
                Tool(
                    name="web_request",
                    description="Make HTTP requests to the target application",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"], "default": "GET"},
                            "path": {"type": "string", "description": "Path to request (e.g., /login, /admin)"},
                            "headers": {"type": "object", "description": "HTTP headers to include"},
                            "data": {"type": "object", "description": "Request body data (for POST, PUT, etc.)"},
                            "params": {"type": "object", "description": "URL query parameters"}
                        },
                        "required": ["path"]
                    }
                ),
                Tool(
                    name="analyze_with_ai",
                    description="Analyze web responses or vulnerabilities using AI via OpenRouter",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content": {"type": "string", "description": "Content to analyze (HTML, response, etc.)"},
                            "analysis_type": {"type": "string", "enum": ["vulnerability_scan", "response_analysis", "payload_generation"], "description": "Type of analysis to perform"},
                            "model": {"type": "string", "default": "anthropic/claude-3.5-sonnet", "description": "OpenRouter model to use"}
                        },
                        "required": ["content", "analysis_type"]
                    }
                ),
                Tool(
                    name="security_scan",
                    description="Perform automated security scanning of specific endpoints",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_type": {"type": "string", "enum": ["sql_injection", "xss", "directory_traversal", "command_injection"], "description": "Type of security scan to perform"},
                            "target_path": {"type": "string", "description": "Specific path to scan"},
                            "parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameters to test (form fields, URL params, etc.)"}
                        },
                        "required": ["scan_type", "target_path"]
                    }
                ),
                Tool(
                    name="spider_application",
                    description="Crawl the web application to discover endpoints and forms",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "max_depth": {"type": "integer", "default": 3, "description": "Maximum crawl depth"},
                            "follow_external": {"type": "boolean", "default": False, "description": "Whether to follow external links"}
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            logger.info(f"@@@ MCP_SERVER: handle_call_tool called for tool '{name}' with arguments: {arguments}")
            try:
                if name == "web_request":
                    return await self.handle_web_request(arguments)
                elif name == "analyze_with_ai":
                    return await self.handle_ai_analysis(arguments)
                elif name == "security_scan":
                    return await self.handle_security_scan(arguments)
                elif name == "spider_application":
                    return await self.handle_spider_application(arguments)
                else:
                    logger.warning(f"@@@ MCP_SERVER: Unknown tool called: {name}")
                    raise ValueError(f"Unknown tool: {name}")
            except Exception as e:
                logger.error(f"@@@ MCP_SERVER: Error in tool '{name}': {str(e)}", exc_info=True)
                return [TextContent(type="text", text=f"Error executing tool {name}: {str(e)}")]
    
    async def handle_web_request(self, args: Dict[str, Any]) -> List[TextContent]:
        logger.info(f"@@@ MCP_SERVER: Entered handle_web_request with args: {args}")
        method = args.get("method", "GET")
        path = args.get("path", "/") # Default path to prevent errors if missing
        headers = args.get("headers", {})
        data = args.get("data", None) # Use None for GET, allow empty dict for POST
        params = args.get("params", {})
        
        full_url = urljoin(self.target_url, path)
        logger.info(f"@@@ MCP_SERVER: Web Request - Method: {method}, URL: {full_url}, Params: {params}, Data: {data}")

        try:
            if not self.session or self.session.closed:
                # Consider adding connector options like SSL verification disabling if needed for specific targets
                # connector = aiohttp.TCPConnector(ssl=False) # Example for disabling SSL verify
                self.session = aiohttp.ClientSession() # connector=connector
            
            async with self.session.request(
                method=method,
                url=full_url,
                headers=headers,
                json=data if method not in ["GET", "HEAD"] and data is not None else None, # Send data as JSON for relevant methods
                params=params,
                timeout=aiohttp.ClientTimeout(total=30) # 30-second timeout for web requests
            ) as response:
                response_text = await response.text()
                logger.info(f"@@@ MCP_SERVER: Web Request to {full_url} - Status: {response.status}, Response (first 200 chars): {response_text[:200]}")
                
                result_data = {
                    "url": str(response.url),
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body_snippet": response_text[:5000], # Truncate large responses
                    "full_body_length": len(response_text),
                    "method": method
                }
                
                return [TextContent(
                    type="text",
                    text=f"HTTP {method} {full_url}\nStatus: {response.status}\n\nResponse details:\n{json.dumps(result_data, indent=2)}"
                )]
        
        except aiohttp.ClientTimeout as timeout_err:
            logger.error(f"@@@ MCP_SERVER: Web Request to {full_url} timed out: {timeout_err}", exc_info=True)
            return [TextContent(type="text", text=f"Request to {full_url} failed: Timeout")]
        except aiohttp.ClientError as client_err:
            logger.error(f"@@@ MCP_SERVER: Web Request to {full_url} failed with ClientError: {client_err}", exc_info=True)
            return [TextContent(type="text", text=f"Request to {full_url} failed: {client_err}")]
        except Exception as e:
            logger.error(f"@@@ MCP_SERVER: Web Request to {full_url} failed with Exception: {str(e)}", exc_info=True)
            return [TextContent(type="text", text=f"Request to {full_url} failed: {str(e)}")]

    async def handle_ai_analysis(self, args: Dict[str, Any]) -> List[TextContent]:
        logger.info(f"@@@ MCP_SERVER: Entered handle_ai_analysis with args: {args}")
        content = args.get("content", "") # Default to empty string if content is missing
        analysis_type = args.get("analysis_type")
        model = args.get("model", "anthropic/claude-3.5-sonnet")

        if not analysis_type:
            logger.error("@@@ MCP_SERVER: AI Analysis - 'analysis_type' is a required argument.")
            return [TextContent(type="text", text="AI analysis failed: 'analysis_type' is required.")]
        
        prompts = {
            "vulnerability_scan": f"Analyze the following web application response for security vulnerabilities:\n\n{content}\n\nLook for:\n- SQL injection opportunities\n- Cross-site scripting (XSS) vulnerabilities\n- Authentication bypasses\n- Information disclosure\n- Input validation issues\n- Directory traversal possibilities\n\nProvide specific findings and potential exploit methods. Be concise and actionable.",
            "response_analysis": f"Analyze this HTTP response for interesting security-relevant information:\n\n{content}\n\nFocus on:\n- Error messages that reveal system information\n- Hidden form fields or parameters\n- Comments in HTML/JavaScript\n- Technology stack indicators\n- Potential attack vectors. Be concise.",
            "payload_generation": f"Based on this web application context or vulnerability description:\n\n{content}\n\nGenerate targeted, ready-to-use security testing payloads for the identified context. Explain each payload briefly. Focus on common web vulnerabilities like SQLi, XSS, Command Injection, Directory Traversal."
        }
        
        prompt = prompts.get(analysis_type)
        if not prompt:
            logger.error(f"@@@ MCP_SERVER: AI Analysis - Invalid 'analysis_type': {analysis_type}")
            return [TextContent(type="text", text=f"AI analysis failed: Invalid 'analysis_type': {analysis_type}. Valid types are: {list(prompts.keys())}")]
        
        logger.info(f"@@@ MCP_SERVER: AI Analysis - Using model '{model}' for type '{analysis_type}'.")

        try:
            headers = {
                "Authorization": f"Bearer {self.openrouter_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost", # Some models like it, or your site
                "X-Title": "MCP Security Test Client" # Optional custom header
            }
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}]
            }
            
            # Truncate prompt for logging if it's too long
            log_payload_prompt = prompt[:200] + "..." if len(prompt) > 200 else prompt
            log_payload_for_print = {"model": model, "messages": [{"role": "user", "content": log_payload_prompt}]}
            logger.info(f"@@@ MCP_SERVER: AI Analysis - Making request to OpenRouter. Payload (truncated prompt): {json.dumps(log_payload_for_print, indent=2)}")
            
            request_timeout = aiohttp.ClientTimeout(total=120) # 120 seconds total timeout for AI calls

            if not self.session or self.session.closed:
                self.session = aiohttp.ClientSession()

            async with self.session.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=request_timeout # Apply timeout to the post request
            ) as response:
                response_status = response.status
                logger.info(f"@@@ MCP_SERVER: AI Analysis - Received OpenRouter status: {response_status}")
                response_text = await response.text()
                logger.info(f"@@@ MCP_SERVER: AI Analysis - Received OpenRouter response (first 500 chars): {response_text[:500]}")
                
                result = json.loads(response_text) # Attempt to parse JSON
                    
                if response_status == 200:
                    ai_response_content = result.get("choices", [{}])[0].get("message", {}).get("content")
                    if ai_response_content is None:
                        logger.error(f"@@@ MCP_SERVER: AI Analysis - Could not extract AI content from OpenRouter response. Full response: {result}")
                        ai_response_content = "Error: Could not extract AI response content from successful API call."
                    else:
                        logger.info(f"@@@ MCP_SERVER: AI Analysis - Success. Returning AI response (first 100 chars): {ai_response_content[:100]}...")
                    return [TextContent(type="text", text=f"AI Analysis Result ({analysis_type} with {model}):\n\n{ai_response_content}")]
                else:
                    error_detail = result.get("error", {})
                    error_msg = error_detail.get("message", "Unknown error from OpenRouter")
                    logger.error(f"@@@ MCP_SERVER: AI Analysis - OpenRouter API error ({response_status}): {error_msg} | Full detail: {result}")
                    return [TextContent(type="text", text=f"OpenRouter API error ({response_status}): {error_msg}")]
        
        except aiohttp.ClientTimeout as timeout_err:
            logger.error(f"@@@ MCP_SERVER: AI Analysis - Request to OpenRouter timed out after {request_timeout.total if request_timeout else 'N/A'}s: {timeout_err}", exc_info=True)
            return [TextContent(type="text", text=f"AI analysis failed: Request to OpenRouter timed out.")]
        except aiohttp.ClientError as client_err:
            logger.error(f"@@@ MCP_SERVER: AI Analysis - aiohttp.ClientError: {client_err}", exc_info=True)
            return [TextContent(type="text", text=f"AI analysis failed due to a client connection error: {client_err}")]
        except json.JSONDecodeError as decode_err:
             logger.error(f"@@@ MCP_SERVER: AI Analysis - Failed to decode JSON response from OpenRouter: {decode_err}. Response text was: {response_text[:500] if 'response_text' in locals() else 'N/A'}", exc_info=True)
             return [TextContent(type="text", text=f"AI analysis failed: Could not decode response from AI service.")]
        except Exception as e:
            logger.error(f"@@@ MCP_SERVER: AI Analysis - Unexpected exception: {str(e)}", exc_info=True)
            return [TextContent(type="text", text=f"AI analysis failed unexpectedly: {str(e)}")]
    
    async def handle_security_scan(self, args: Dict[str, Any]) -> List[TextContent]:
        logger.info(f"@@@ MCP_SERVER: Entered handle_security_scan with args: {args}")
        scan_type = args.get("scan_type")
        target_path = args.get("target_path")
        parameters = args.get("parameters", [])

        if not scan_type or not target_path:
            logger.error("@@@ MCP_SERVER: Security Scan - 'scan_type' and 'target_path' are required.")
            return [TextContent(type="text", text="Security scan failed: 'scan_type' and 'target_path' are required.")]

        payloads_db = {
            "sql_injection": ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT null, null, null--", "admin'--", "' OR 1=1#"],
            "xss": ["<script>alert('XSS')</script>", "javascript:alert('XSS')", "<img src=x onerror=alert('XSS')>", "'\"><script>alert('XSS')</script>", "<svg onload=alert('XSS')>"],
            "directory_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
            "command_injection": ["; ls -la", "| whoami", "&& cat /etc/passwd", "`id`", "$(whoami)"]
        }
        
        scan_payloads = payloads_db.get(scan_type, [])
        if not scan_payloads:
            logger.warning(f"@@@ MCP_SERVER: Security Scan - No payloads defined for scan_type '{scan_type}'")
            return [TextContent(type="text", text=f"No payloads defined for scan_type '{scan_type}'. Valid types are: {list(payloads_db.keys())}")]
            
        results = []
        logger.info(f"@@@ MCP_SERVER: Security Scan - Starting '{scan_type}' on '{target_path}' with params {parameters}")

        for payload_item in scan_payloads:
            # Test each parameter (if provided) or as a general payload (if no params specified)
            test_params_list = parameters if parameters else [""] # If no params, test payload in general (e.g. path or body)

            for param_name in test_params_list:
                try:
                    full_url = urljoin(self.target_url, target_path)
                    
                    if not self.session or self.session.closed:
                        self.session = aiohttp.ClientSession()
                    
                    # Try both GET and POST methods, or adapt based on scan type/target knowledge
                    for http_method in ['GET', 'POST']:
                        # Construct data/params based on whether a specific parameter is being targeted
                        request_params = {}
                        request_data = None

                        if http_method == 'GET':
                            request_params = {param_name: payload_item} if param_name else {}
                            # If no specific param, and GET, it's harder to inject general payloads directly unless part of path
                            # This simplified scanner assumes param injection for GET.
                        else: # POST
                            request_data = {param_name: payload_item} if param_name else { "generic_payload_field": payload_item }
                        
                        logger.info(f"@@@ MCP_SERVER: Security Scan - Testing {http_method} {full_url} | Param: '{param_name}' | Payload: '{payload_item}'")
                        async with self.session.request(
                            method=http_method,
                            url=full_url,
                            params=request_params if http_method == 'GET' else None,
                            data=request_data if http_method == 'POST' else None, # Send as form data by default for POST
                            timeout=aiohttp.ClientTimeout(total=10) # Shorter timeout for scan probes
                        ) as response:
                            response_text = await response.text()
                            
                            vulnerable = False
                            # Simplified detection logic
                            if scan_type == "sql_injection" and any(ind in response_text.lower() for ind in ["sql syntax", "warning: mysql", "unclosed quotation mark"]):
                                vulnerable = True
                            elif scan_type == "xss" and payload_item in response_text: # Reflective XSS check
                                vulnerable = True
                            # Add more sophisticated checks as needed

                            if vulnerable or response.status >= 500: # High status also interesting
                                results.append({
                                    "method": http_method,
                                    "parameter_tested": param_name if param_name else "N/A (general)",
                                    "payload": payload_item,
                                    "status_code": response.status,
                                    "vulnerable_indication": vulnerable,
                                    "response_snippet": response_text[:200]
                                })
                                logger.info(f"@@@ MCP_SERVER: Security Scan - Potential finding: {results[-1]}")
                
                except Exception as e:
                    logger.error(f"@@@ MCP_SERVER: Security Scan - Error testing payload '{payload_item}' on param '{param_name}': {e}", exc_info=True)
                    results.append({
                        "method": "ERROR",
                        "parameter_tested": param_name if param_name else "N/A",
                        "payload": payload_item,
                        "error_message": str(e)
                    })
        
        logger.info(f"@@@ MCP_SERVER: Security Scan - Completed for '{scan_type}'. Found {len(results)} potential items.")
        return [TextContent(
            type="text",
            text=f"Security scan '{scan_type}' results for '{target_path}':\n\n{json.dumps(results, indent=2)}"
        )]
    
    async def handle_spider_application(self, args: Dict[str, Any]) -> List[TextContent]:
        logger.info(f"@@@ MCP_SERVER: Entered handle_spider_application with args: {args}")
        max_depth = args.get("max_depth", 2) # Reduced default for quicker tests
        follow_external = args.get("follow_external", False)
        
        discovered_urls = set()
        forms_found = []
        urls_to_visit = asyncio.Queue()
        
        start_url = self.target_url.rstrip('/')
        await urls_to_visit.put((start_url, 0))
        discovered_urls.add(start_url)
        
        processed_count = 0

        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession()

        while not urls_to_visit.empty() and processed_count < 100: # Limit processed URLs to prevent runaway spider
            current_url, current_depth = await urls_to_visit.get()
            urls_to_visit.task_done()
            processed_count += 1

            if current_depth > max_depth:
                continue
            
            logger.info(f"@@@ MCP_SERVER: Spider - Crawling URL (Depth {current_depth}): {current_url}")
            
            try:
                async with self.session.get(current_url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as response:
                    if response.status == 200 and response.content_type and 'text/html' in response.content_type.lower():
                        html_content = await response.text()
                        
                        # Using regex for simplicity, BeautifulSoup4 would be more robust
                        import re
                        
                        # Find links
                        # More robust regex for hrefs, trying to capture relative and absolute
                        base_url_parsed = urlparse(str(response.url)) # Use actual response URL after redirects
                        
                        for link_match in re.finditer(r'href\s*=\s*[\'"]([^\'"#\s]+)[^\'"]*[\'"]', html_content, re.IGNORECASE):
                            link = link_match.group(1).strip()
                            if not link or link.startswith(('javascript:', 'mailto:', 'tel:')):
                                continue

                            abs_link = urljoin(f"{base_url_parsed.scheme}://{base_url_parsed.netloc}{base_url_parsed.path}", link)
                            abs_link_parsed = urlparse(abs_link)
                            
                            # Normalize: remove fragment and trailing slash
                            abs_link_normalized = f"{abs_link_parsed.scheme}://{abs_link_parsed.netloc}{abs_link_parsed.path.rstrip('/')}"
                            if not abs_link_parsed.query: # Add query back if it exists
                                pass # query is part of path if path includes it from urljoin
                            else:
                                abs_link_normalized += "?"+abs_link_parsed.query


                            if abs_link_normalized not in discovered_urls:
                                if abs_link_normalized.startswith(self.target_url.rstrip('/')) or \
                                   (follow_external and urlparse(abs_link_normalized).netloc != urlparse(self.target_url).netloc):
                                    
                                    # Check if it's within the same domain or configured target scope
                                    if urlparse(abs_link_normalized).netloc == urlparse(self.target_url).netloc:
                                        discovered_urls.add(abs_link_normalized)
                                        await urls_to_visit.put((abs_link_normalized, current_depth + 1))
                                        logger.debug(f"@@@ MCP_SERVER: Spider - Queued: {abs_link_normalized}")
                        
                        # Find forms (very basic)
                        for form_match in re.finditer(r'<form[^>]*action\s*=\s*[\'"]([^\'"]*)[\'"][^>]*method\s*=\s*[\'"]([^\'"]*)[\'"][^>]*>(.*?)</form>', html_content, re.IGNORECASE | re.DOTALL):
                            action, method, form_body = form_match.groups()
                            inputs = re.findall(r'<input[^>]*name\s*=\s*[\'"]([^\'"]*)[\'"]', form_body, re.IGNORECASE)
                            forms_found.append({
                                "url": current_url,
                                "action": action,
                                "method": method.upper(),
                                "inputs": inputs
                            })
                            logger.info(f"@@@ MCP_SERVER: Spider - Found form on {current_url}: action='{action}', method='{method}'")
            
            except aiohttp.ClientTimeout:
                logger.warning(f"@@@ MCP_SERVER: Spider - Timeout crawling {current_url}")
            except aiohttp.ClientError as ce:
                logger.warning(f"@@@ MCP_SERVER: Spider - ClientError crawling {current_url}: {ce}")
            except Exception as e:
                logger.error(f"@@@ MCP_SERVER: Spider - Error crawling {current_url}: {str(e)}", exc_info=True)
        
        logger.info(f"@@@ MCP_SERVER: Spider - Crawling complete. Discovered {len(discovered_urls)} URLs, {len(forms_found)} forms.")
        result_data = {
            "discovered_urls": sorted(list(discovered_urls)),
            "forms_found": forms_found,
        }
        
        return [TextContent(
            type="text",
            text=f"Spider results (max_depth {max_depth}):\n\n{json.dumps(result_data, indent=2)}"
        )]
    
    async def cleanup(self):
        """Clean up resources like the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()
            logger.info("@@@ MCP_SERVER: Global aiohttp session closed.")
    
    async def run(self):
        """Run the MCP server's main loop."""
        logger.info("@@@ MCP_SERVER: Starting server run loop...")
        try:
            # stdio_server provides read_stream and write_stream for stdin/stdout
            async with stdio_server() as (read_stream, write_stream):
                logger.info("@@@ MCP_SERVER: stdio_server context entered. Initializing MCP server...")
                await self.server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name="security-testing-mcp",
                        server_version="1.0.0",
                        capabilities=self.server.get_capabilities(
                            notification_options=NotificationOptions(), # MODIFIED: Use instantiated NotificationOptions
                            experimental_capabilities={} # Keep as dict as per previous findings
                        ),
                    ),
                )
                logger.info("@@@ MCP_SERVER: self.server.run completed.")
        except Exception as e:
            logger.error(f"@@@ MCP_SERVER: Exception in server run loop: {e}", exc_info=True)
        finally:
            logger.info("@@@ MCP_SERVER: Server run loop finished. Cleaning up...")
            await self.cleanup()
            logger.info("@@@ MCP_SERVER: Cleanup complete. Server shutting down.")

if __name__ == "__main__":
    # Initial print statements in __init__ will appear before this
    print("🚀 MCP_SERVER_MAIN: Launching MCP Security Server...")
    server_instance = SecurityTestingMCPServer()
    try:
        asyncio.run(server_instance.run())
    except KeyboardInterrupt:
        print("\n🛑 MCP_SERVER_MAIN: Server interrupted by user (KeyboardInterrupt).")
    except Exception as e:
        # This will catch exceptions from __init__ if they weren't ValueError
        print(f"❌ MCP_SERVER_MAIN: Critical error during server startup or run: {e}")
        logger.error(f"@@@ MCP_SERVER_MAIN: Critical error: {e}", exc_info=True)
    finally:
        print("ℹ️ MCP_SERVER_MAIN: Server process attempting to exit.")
