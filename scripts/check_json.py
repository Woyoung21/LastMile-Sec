import json
from pathlib import Path

# Check one of the JSON files
json_file = Path('data/processed/Vulnerability Scan Report CSV_44f40b18.json')

if json_file.exists():
    with open(json_file) as f:
        data = json.load(f)
    
    print(f'File size: {json_file.stat().st_size} bytes')
    print(f'Number of findings: {len(data.get("findings", []))}')
    
    if data.get('findings'):
        first = data['findings'][0]
        print(f'\nFirst finding keys: {list(first.keys())}')
        print(f'Has metadata field: {"metadata" in first}')
        if 'metadata' in first:
            print(f'Metadata: {first["metadata"]}')
else:
    print('File not found')
