#!/usr/bin/env python3
"""
Debug script to check environment variables and .env file loading
"""
import os
from dotenv import load_dotenv

def debug_environment():
    print("🔍 Environment Debug Information")
    print("=" * 50)
    
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
                    # Hide API key for security
                    if 'OPENROUTER_API_KEY' in line and '=' in line:
                        key, value = line.split('=', 1)
                        masked_value = value[:10] + '*' * (len(value) - 10) if len(value) > 10 else '*' * len(value)
                        print(f"  Line {i}: {key}={masked_value}")
                    else:
                        print(f"  Line {i}: {line.strip()}")
        except Exception as e:
            print(f"  Error reading .env file: {e}")
    
    print("\n🔧 Before loading .env:")
    print(f"  OPENROUTER_API_KEY: {'Set' if os.getenv('OPENROUTER_API_KEY') else 'Not set'}")
    print(f"  TARGET_URL: {os.getenv('TARGET_URL', 'Not set')}")
    
    # Load environment variables
    print("\n⚡ Loading .env file...")
    load_dotenv()
    
    print("\n✅ After loading .env:")
    api_key = os.getenv('OPENROUTER_API_KEY')
    target_url = os.getenv('TARGET_URL')
    
    print(f"  OPENROUTER_API_KEY: {'Set (' + api_key[:20] + '...)' if api_key else 'Not set'}")
    print(f"  TARGET_URL: {target_url}")
    
    # Check if API key looks valid
    if api_key:
        if api_key.startswith('sk-or-'):
            print("  ✅ API key format looks correct")
        else:
            print("  ⚠️  API key format might be incorrect (should start with 'sk-or-')")
    
    print("\n🌍 All environment variables:")
    env_vars = dict(os.environ)
    for key in sorted(env_vars.keys()):
        if 'API' in key or 'KEY' in key or 'TOKEN' in key:
            value = env_vars[key]
            masked = value[:10] + '*' * max(0, len(value) - 10) if len(value) > 10 else '*' * len(value)
            print(f"  {key}: {masked}")
        elif key in ['TARGET_URL', 'OPENROUTER_MODEL', 'LOG_LEVEL']:
            print(f"  {key}: {env_vars[key]}")

if __name__ == "__main__":
    debug_environment()