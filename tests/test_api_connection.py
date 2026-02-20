"""
Simple test to verify Gemini API connection and configuration
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    print("❌ Error: GOOGLE_API_KEY not found in .env file")
    exit(1)

print("✓ Found GOOGLE_API_KEY in environment")

# Test 1: Try using google.genai (newer package)
try:
    print("\n🔍 Testing google.genai package...")
    import google.genai as genai
    genai.configure(api_key=api_key)
    
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents="Say hello!"
    )
    
    print(f"✓ google.genai works!")
    print(f"  Response: {response.text}")
    
except Exception as e:
    print(f"✗ google.genai failed: {e}")

# Test 2: Try using google.generativeai (older package - fallback)
try:
    print("\n🔍 Testing google.generativeai package (deprecated)...")
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    
    model = genai.GenerativeModel("gemini-2.0-flash")
    response = model.generate_content("Say hello!")
    
    print(f"✓ google.generativeai works!")
    print(f"  Response: {response.text}")
    
except Exception as e:
    print(f"✗ google.generativeai failed: {e}")

# Test 3: Test LangExtract setup
try:
    print("\n🔍 Testing LangExtract setup...")
    os.environ["LANGEXTRACT_API_KEY"] = api_key
    
    import langextract as lx
    print(f"✓ LangExtract imported successfully")
    print(f"  Version: {lx.__version__ if hasattr(lx, '__version__') else 'unknown'}")
    
except Exception as e:
    print(f"✗ LangExtract import failed: {e}")

print("\n" + "="*60)
print("✅ API Configuration test complete!")
print("="*60)
