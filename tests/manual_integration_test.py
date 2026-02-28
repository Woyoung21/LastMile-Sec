import os
import sys
import json
import torch
from pathlib import Path

# Ensure the src directory is in the path
sys.path.append(str(Path(__file__).parent))

from src.section2_report_map.reporter import Reporter
from src.section2_report_map.mapper import Mapper

def run_system_test():
    print("🛡️  LastMile-Sec: Full System Integration Test")
    print("-" * 50)

    # 1. Initialize Agents
    try:
        print("🤖 Initializing Reporter (Gemini Cloud)...")
        reporter = Reporter()
        
        print("🧠 Loading Local Mistral-7B LoRA (This may take a minute)...")
        # This will trigger bitsandbytes 4-bit loading on your GPU
        mapper = Mapper(routing_mode="local") 
        print("✅ Models loaded successfully.")
    except Exception as e:
        print(f"❌ Initialization Failed: {e}")
        return

    # 2. Define a Test Security Event (Brute Force leading to Login)
    # This aligns with the "Windows Telemetry" focus in your research paper.
    raw_event = {
        "title": "Multiple Failed System Logons",
        "description": (
            "Source IP 192.168.1.105 attempted 50+ logins to 'Administrator' account "
            "within 2 minutes. Final attempt was successful from the same IP using "
            "NTLM authentication."
        ),
        "services": "Windows Event Log (Security)",
        "ports": "445 (SMB)",
        "cves": ""
    }

    # 3. Step 1: The Reporter Agent (Summarization)
    print("\n📝 Step 1: Reporter Agent is processing...")
    report_json = reporter.report_finding(raw_event)
    summary = report_json['metadata']['technical_summary']
    print(f"👉 Generated Summary: \"{summary}\"")

    # 4. Step 2: The Mapper Agent (RAG + Mistral)
    print("\n🔍 Step 2: Mapper Agent is classifying (querying Actian VectorAI + Mistral)...")
    try:
        mapping_result = mapper.map_finding(report_json)
        
        print(f"\n🎯 Resulting MITRE ATT&CK IDs: {mapping_result.mitre_ids}")
        print(f"📄 Validation Status: {'Passed' if mapping_result.validation_passed else 'Refined by Validator'}")
        print(f"🤖 Engine Used: {mapping_result.metadata['mapping_agent']}")
        print(f"🗄️  Context Source: {mapping_result.metadata['db_context']}")
        
        if mapping_result.reference_examples:
            print(f"📚 RAG: Found {len(mapping_result.reference_examples)} similar historical cases.")
        else:
            print("⚠️ RAG: No historical context found in Actian (Database may be empty).")

    except Exception as e:
        print(f"❌ Mapping Failed: {e}")

    print("\n" + "-" * 50)
    print("Test Complete.")

if __name__ == "__main__":
    run_system_test()