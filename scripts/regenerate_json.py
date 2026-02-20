#!/usr/bin/env python3
"""Regenerate processed JSON files with enhanced parser"""

import json
from datetime import datetime
from pathlib import Path
from src.section1_ingestion.normalizer import Normalizer
from src.section1_ingestion.schemas import IngestedPacket

def regenerate_processed_files():
    """Re-ingest raw files with enhanced parser."""
    raw_dir = Path("data/raw")
    processed_dir = Path("data/processed")
    normalizer = Normalizer()
    
    files_to_process = [
        "Vulnerability Scan Report (By Device).pdf",
        "Vulnerability Scan Report CSV.csv",
    ]
    
    for filename in files_to_process:
        raw_file = raw_dir / filename
        if not raw_file.exists():
            print(f"⚠️  Skipping {filename} - not found")
            continue
        
        print(f"\n📄 Processing {filename}...")
        try:
            # Ingest with enhanced parser
            packet = normalizer.ingest(str(raw_file))
            
            # Generate output filename with timestamp
            clean_name = filename.replace(".pdf", "").replace(".csv", "")
            output_file = processed_dir / f"{clean_name}_enhanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Save with enhanced metadata
            with open(output_file, 'w') as f:
                json.dump(packet.model_dump(mode='json'), f, indent=2)
            
            print(f"✅ Saved {len(packet.findings)} findings to {output_file.name}")
            
            # Show sample finding with metadata
            if packet.findings:
                sample = packet.findings[0]
                print(f"\n  Sample Finding: {sample.title[:60]}")
                if sample.metadata:
                    print(f"    Metadata: {list(sample.metadata.keys())}")
                    for key, val in list(sample.metadata.items())[:3]:
                        print(f"      - {key}: {val}")
        
        except Exception as e:
            print(f"❌ Error processing {filename}: {e}")

if __name__ == "__main__":
    regenerate_processed_files()
