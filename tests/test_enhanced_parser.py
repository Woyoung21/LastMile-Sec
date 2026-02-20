#!/usr/bin/env python3
"""Quick test of enhanced parser"""

from src.section1_ingestion.parsers.pdf_parser import PDFParser

parser = PDFParser('data/raw/Vulnerability Scan Report (By Device).pdf')
findings = parser.parse()

print(f'Total findings: {len(findings)}')
print('\nSample findings with ports/services:')

for i, f in enumerate(findings[:5]):
    print(f'\nFinding {i+1}: {f.title[:60]}')
    if f.metadata.get('ports'):
        print(f'  Ports: {f.metadata["ports"]}')
    if f.metadata.get('services'):
        print(f'  Services: {f.metadata["services"]}')
