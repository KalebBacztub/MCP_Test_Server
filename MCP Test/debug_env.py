#!/usr/bin/env python3
"""
Enhanced debug script to check environment variables and API key issues
"""
import os
import sys
from dotenv import load_dotenv
import aiohttp
import asyncio

def debug_environment():
    print("🔍 Enhanced Environment Debug Information")
    print("=" * 60)
    
    # Check current working directory
    print(f"Current working directory: {os.getcwd()}")
    
    # Check if .env file exists
    env_file_exists = os.path.exists('.env')
    print(f".env file exists: {env_file_exists}")
    
    if env_file_exists:
        print("\n📁 .env file contents:")
        try:
            with open('.env', 'r') as f:
                lines = f.readlines()
                for i, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        print(f"  Line {i}: {line}")
                    elif 'OPENROUTER_API_KEY' in line and '=' in line:
                        key, value = line.split('=', 1)
                        value = value.strip()
                        # Show more of the key for debugging but still mask most
                        if len(value) > 20:
                            masked_value = value[:15] + '*' * (len(value) - 20) + value[-5:]
                        else:
                            masked_value = value[:5] + '*' * max(0, len(value) - 10) + value[-5:] if len(value) > 10 else '*' * len(value)
                        print(f"  Line {i}: {key}={masked_value}")
                        print(f"    Raw length: {len(value)} characters")
                        print(f"    Starts with: {value[:10] if len(value) >= 10 else value}")
                        print(f"    Contains spaces: {'Yes' if ' ' in value else 'No'}")
                        print(f"    Contains newlines: {'Yes' if chr(10) in value else 'No'}")
                    else:
                        print(f"  Line {i}: {line}")
        except Exception as e:
            print(f"  Error reading .env file: {e}")
    
    print("\n🔧 Before loading .env:")
    print(f"  OPENROUTER_API_KEY: {'Set' if os.getenv('OPENROUTER_API_KEY') else 'Not set'}")
    print(f"  TARGET_URL: {os.getenv('TARGET_URL', 'Not set')}")
    
    # Load environment variables
    print("\n⚡ Loading .env file...")
    load_result = load_dotenv()
    print(f"load_dotenv() returned: {load_result}")
    
    print("\n✅ After loading .env:")
    api_key = os.getenv('OPENROUTER_API_KEY')
    target_url = os.getenv('TARGET_URL')
    model = os.getenv('OPENROUTER_MODEL')
    log_level = os.getenv('LOG_LEVEL')
    
    print(f"  OPENROUTER_API_KEY: {'Set' if api_key else 'Not set'}")
    if api_key:
        print(f"    Length: {len(api_key)} characters")
        print(f"    First 15 chars: {api_key[:15]}")
        print(f"    Last 5 chars: {api_key[-5:]}")
        print(f"    Contains whitespace: {'Yes' if any(c.isspace() for c in api_key) else 'No'}")
        print(f"    Stripped length: {len(api_key.strip())}")
        
        # Check format
        if api_key.startswith('sk-or-v1-'):
            print("    ✅ API key format looks correct (starts with sk-or-v1-)")
        elif api_key.startswith('sk-or-'):
            print("    ⚠️  API key starts with sk-or- but not sk-or-v1-")
        else:
            print("    ❌ API key format looks incorrect (should start with 'sk-or-')")
    
    print(f"  TARGET_URL: {target_url}")
    print(f"  OPENROUTER_MODEL: {model}")
    print(f"  LOG_LEVEL: {log_level}")
    
    return api_key, target_url

async def test_api_key(api_key):
    """Test the API key with OpenRouter"""
    if not api_key:
        print("\n❌ No API key to test")
        return False
    
    print(f"\n🧪 Testing API key with OpenRouter...")
    
    # Clean the API key (remove any whitespace)
    clean_api_key = api_key.strip()
    
    headers = {
        'Authorization': f'Bearer {clean_api_key}',
        'Content-Type': 'application/json',
        'User-Agent': 'MCP-Security-Server/1.0'
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            # Test with models endpoint (lightweight)
            async with session.get(
                'https://openrouter.ai/api/v1/models',
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                print(f"  Status Code: {response.status}")
                print(f"  Response Headers: {dict(response.headers)}")
                
                if response.status == 200:
                    result = await response.json()
                    model_count = len(result.get('data', []))
                    print(f"  ✅ API key works! Found {model_count} available models")
                    return True
                elif response.status == 401:
                    error_text = await response.text()
                    print(f"  ❌ Authentication failed (401)")
                    print(f"  Response: {error_text}")
                    return False
                elif response.status == 403:
                    error_text = await response.text()
                    print(f"  ❌ Forbidden (403) - API key might be invalid or expired")
                    print(f"  Response: {error_text}")
                    return False
                else:
                    error_text = await response.text()
                    print(f"  ⚠️  Unexpected status code: {response.status}")
                    print(f"  Response: {error_text}")
                    return False
                    
    except aiohttp.ClientError as e:
        print(f"  ❌ Network error: {e}")
        return False
    except asyncio.TimeoutError:
        print(f"  ❌ Request timed out")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False

async def test_target_url(target_url):
    """Test connectivity to target URL"""
    if not target_url:
        print("\n❌ No target URL to test")
        return False
    
    print(f"\n🎯 Testing target URL: {target_url}")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                target_url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                print(f"  Status Code: {response.status}")
                content_type = response.headers.get('content-type', 'unknown')
                print(f"  Content-Type: {content_type}")
                content_length = len(await response.text())
                print(f"  Content Length: {content_length} bytes")
                print(f"  ✅ Target is accessible")
                return True
                
    except aiohttp.ClientError as e:
        print(f"  ❌ Connection error: {e}")
        return False
    except asyncio.TimeoutError:
        print(f"  ❌ Connection timed out")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False

def suggest_fixes():
    """Suggest potential fixes for common issues"""
    print("\n🔧 Troubleshooting Suggestions:")
    print("=" * 40)
    
    print("\n1. API Key Issues:")
    print("   - Make sure there are no extra spaces before/after the API key")
    print("   - Verify the key starts with 'sk-or-v1-'")
    print("   - Check if the key was copied completely (they're quite long)")
    print("   - Ensure the key hasn't expired or been revoked")
    
    print("\n2. .env File Issues:")
    print("   - Make sure there are no spaces around the = sign")
    print("   - Don't use quotes around the values")
    print("   - Ensure the file is named exactly '.env' (not 'env.txt' or similar)")
    print("   - Check file encoding (should be UTF-8)")
    
    print("\n3. Quick Fixes:")
    print("   - Try recreating the .env file from scratch")
    print("   - Copy the API key directly from OpenRouter dashboard")
    print("   - Use export to test: export OPENROUTER_API_KEY='your-key-here'")
    
    print("\n4. Manual Test:")
    print("   curl -H 'Authorization: Bearer YOUR_API_KEY' \\")
    print("        https://openrouter.ai/api/v1/models")

async def main():
    print("🚀 MCP Security Server - Environment Diagnostics")
    print("=" * 60)
    
    # Debug environment
    api_key, target_url = debug_environment()
    
    # Test API key
    api_success = await test_api_key(api_key)
    
    # Test target URL
    target_success = await test_target_url(target_url)
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 DIAGNOSTIC SUMMARY")
    print("=" * 60)
    print(f"Environment file loaded: {'✅' if os.path.exists('.env') else '❌'}")
    print(f"API key present: {'✅' if api_key else '❌'}")
    print(f"API key valid: {'✅' if api_success else '❌'}")
    print(f"Target URL accessible: {'✅' if target_success else '❌'}")
    
    if not (api_success and target_success):
        suggest_fixes()
    else:
        print("\n🎉 All checks passed! Your environment is ready.")

if __name__ == "__main__":
    asyncio.run(main())